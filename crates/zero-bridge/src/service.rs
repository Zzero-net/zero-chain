//! Bridge service — the main event loop for a Trinity Validator.
//!
//! Orchestrates:
//!   1. Polling Ethereum RPC for new Deposited events (bridge-in)
//!   2. Signing deposits and sharing with peers (Ed25519 attestations)
//!   3. Signing release requests and sharing with peers (ECDSA / EIP-712)
//!   4. Executing operations when signature threshold is met
//!   5. Periodic cleanup of stale pending operations

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use ed25519_dalek::{Signer, SigningKey};

use crate::config::{BridgeConfig, VaultConfig};
use crate::coordinator::{OpType, SignatureCollector};
use crate::eip712::{Eip712Signer, ReleaseParams};
use crate::http::{self, AppState, ThresholdEvent};
use crate::rpc::EthRpc;
use zero_storage::BridgeOp;

/// Per-chain watcher state.
struct ChainWatcher {
    config: VaultConfig,
    rpc: EthRpc,
    last_block: u64,
}

/// The bridge service daemon.
pub struct BridgeService {
    config: BridgeConfig,
    signer: Eip712Signer,
    ecdsa_key: [u8; 32],
    ed25519_signing_key: SigningKey,
    ed25519_pubkey: [u8; 32],
    http_client: reqwest::Client,
}

impl BridgeService {
    /// Create a new bridge service from config.
    pub fn new(config: BridgeConfig, ecdsa_key: [u8; 32]) -> Result<Self, anyhow::Error> {
        // Use the first vault's chain info for the signer.
        // In production, each chain would have its own signer instance.
        let first_vault = config.vaults.first()
            .ok_or_else(|| anyhow::anyhow!("no vaults configured"))?;
        let vault_addr = BridgeConfig::vault_address_bytes(&first_vault.vault_address)?;

        let signer = Eip712Signer::new(&ecdsa_key, first_vault.chain_id, vault_addr)
            .map_err(|e| anyhow::anyhow!("failed to create signer: {}", e))?;

        // Load Ed25519 signing key for Zero chain attestations
        let ed_key_bytes = std::fs::read(&config.trinity.ed25519_key_file)
            .map_err(|e| anyhow::anyhow!("failed to read ed25519 key: {}", e))?;
        let ed_key: [u8; 32] = hex::decode(
            ed_key_bytes.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect::<Vec<u8>>()
        )
            .map_err(|e| anyhow::anyhow!("invalid ed25519 key hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed25519 key must be 32 bytes"))?;
        let ed25519_signing_key = SigningKey::from_bytes(&ed_key);
        let ed25519_pubkey = ed25519_signing_key.verifying_key().to_bytes();

        info!(
            address = hex::encode(signer.address),
            ed25519_pubkey = hex::encode(ed25519_pubkey),
            chain_id = first_vault.chain_id,
            "Trinity Validator initialized (ECDSA + Ed25519)"
        );

        Ok(Self {
            config,
            signer,
            ecdsa_key,
            ed25519_signing_key,
            ed25519_pubkey,
            http_client: reqwest::Client::new(),
        })
    }

    /// Run the bridge service.
    pub async fn run(self) -> Result<(), anyhow::Error> {
        let listen_addr = self.config.listen_addr.clone();
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        // Build guardian list from config
        let guardians = self.guardians_from_config()?;
        let trinity_pubkeys = self.trinity_pubkeys_from_config()?;

        let collector = SignatureCollector::new(guardians, trinity_pubkeys);

        // Channel for threshold-met notifications
        let (threshold_tx, mut threshold_rx) = mpsc::channel::<ThresholdEvent>(64);

        let state = Arc::new(AppState {
            collector: Mutex::new(collector),
            threshold_tx,
        });

        // Start HTTP coordination server
        let router = http::router(state.clone());
        let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
        info!(addr = %listen_addr, "coordination API listening");

        let _http_handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, router).await {
                error!(err = %e, "HTTP server error");
            }
        });

        // Initialize per-chain watchers
        let mut watchers: Vec<ChainWatcher> = Vec::new();
        for vault_config in &self.config.vaults {
            let rpc = EthRpc::new(&vault_config.rpc_url, &vault_config.chain);
            match rpc.block_number().await {
                Ok(block) => {
                    info!(
                        chain = %vault_config.chain,
                        block,
                        vault = %vault_config.vault_address,
                        "connected to chain"
                    );
                    watchers.push(ChainWatcher {
                        config: vault_config.clone(),
                        rpc,
                        last_block: block,
                    });
                }
                Err(e) => {
                    warn!(
                        chain = %vault_config.chain,
                        err = %e,
                        "failed to connect — will retry"
                    );
                    watchers.push(ChainWatcher {
                        config: vault_config.clone(),
                        rpc,
                        last_block: 0,
                    });
                }
            }
        }

        let peer_endpoints: Vec<String> = self.config.peers
            .iter()
            .map(|p| p.endpoint.clone())
            .collect();

        info!(
            vaults = watchers.len(),
            peers = peer_endpoints.len(),
            poll_ms = self.config.poll_interval_ms,
            "bridge service started"
        );

        // Cleanup interval — every 5 minutes
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(300));
        cleanup_interval.tick().await; // skip first immediate tick

        // Poll interval
        let mut poll = tokio::time::interval(poll_interval);
        poll.tick().await; // skip first immediate tick

        loop {
            tokio::select! {
                // Poll chains for new deposits
                _ = poll.tick() => {
                    for watcher in &mut watchers {
                        if let Err(e) = self.poll_chain(watcher, &state).await {
                            warn!(
                                chain = %watcher.config.chain,
                                err = %e,
                                "poll error"
                            );
                        }
                    }
                }

                // Handle threshold-met events
                Some(event) = threshold_rx.recv() => {
                    self.handle_threshold_met(event, &peer_endpoints, &watchers, &state).await;
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    let mut collector = state.collector.lock().await;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let before = collector.pending_count();
                    collector.cleanup_stale(now, 3600); // 1 hour max age
                    let cleaned = before - collector.pending_count();
                    if cleaned > 0 {
                        info!(cleaned, remaining = collector.pending_count(), "cleaned stale operations");
                    }
                }
            }
        }

        // The compiler needs this even though the loop is infinite
        #[allow(unreachable_code)]
        {
            _http_handle.abort();
            Ok(())
        }
    }

    /// Poll a single chain for new deposit events.
    async fn poll_chain(
        &self,
        watcher: &mut ChainWatcher,
        state: &Arc<AppState>,
    ) -> Result<(), anyhow::Error> {
        let current_block = watcher.rpc.block_number().await?;

        // Need enough confirmations
        let safe_block = current_block.saturating_sub(watcher.config.confirmations);
        if safe_block <= watcher.last_block {
            return Ok(()); // No new confirmed blocks
        }

        let logs = watcher.rpc.get_deposit_logs(
            &watcher.config.vault_address,
            watcher.last_block + 1,
            safe_block,
        ).await?;

        for log in &logs {
            match watcher.rpc.parse_deposit_log(log) {
                Ok(deposit) => {
                    info!(
                        chain = %watcher.config.chain,
                        depositor = hex::encode(deposit.depositor),
                        amount = deposit.amount,
                        block = deposit.block_number,
                        "new deposit detected"
                    );

                    // Create operation in coordinator
                    let op_id = deposit.bridge_id();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    let mut collector = state.collector.lock().await;
                    collector.create_operation(op_id, OpType::Mint, None, now);

                    // Sign the mint attestation with our Ed25519 key
                    let z_units = deposit.to_z_units(watcher.config.token_decimals);
                    let mint_op = BridgeOp::Mint {
                        recipient: deposit.zero_recipient,
                        amount: z_units,
                        source_chain: deposit.source_chain.clone(),
                        source_tx: hex::encode(deposit.source_tx),
                    };
                    let signing_bytes = mint_op.signing_bytes();
                    let signature = self.ed25519_signing_key.sign(&signing_bytes);
                    let sig_bytes = signature.to_bytes();

                    // Add our own signature to the collector
                    match collector.add_ed25519_signature(&op_id, &self.ed25519_pubkey, &sig_bytes) {
                        Ok(_) => {
                            info!(
                                op = hex::encode(op_id),
                                z_units,
                                "signed mint attestation (Ed25519)"
                            );
                        }
                        Err(e) => {
                            warn!(op = hex::encode(op_id), err = %e, "failed to add own Ed25519 signature");
                        }
                    }
                    drop(collector);

                    // Share our Ed25519 signature with peers
                    let peer_endpoints: Vec<String> = self.config.peers
                        .iter()
                        .map(|p| p.endpoint.clone())
                        .collect();
                    for endpoint in &peer_endpoints {
                        match http::send_ed25519_to_peer(
                            &self.http_client,
                            endpoint,
                            &op_id,
                            &self.ed25519_pubkey,
                            &sig_bytes,
                        ).await {
                            Ok(()) => info!(peer = %endpoint, "shared Ed25519 mint attestation"),
                            Err(e) => warn!(peer = %endpoint, err = %e, "failed to share mint attestation"),
                        }
                    }
                }
                Err(e) => {
                    warn!(chain = %watcher.config.chain, err = %e, "failed to parse deposit log");
                }
            }
        }

        watcher.last_block = safe_block;
        Ok(())
    }

    /// Handle an operation that has reached signature threshold.
    async fn handle_threshold_met(
        &self,
        event: ThresholdEvent,
        _peer_endpoints: &[String],
        watchers: &[ChainWatcher],
        state: &Arc<AppState>,
    ) {
        match event.op_type {
            OpType::Release => {
                info!(
                    op = hex::encode(event.op_id),
                    sigs_len = event.ecdsa_sigs_sorted.len(),
                    "release threshold met — submitting to vault"
                );

                // Use the first vault for now (production would route by chain)
                if let Some(watcher) = watchers.first() {
                    if let Some(params) = &event.release_params {
                        let vault_addr = match BridgeConfig::vault_address_bytes(
                            &watcher.config.vault_address,
                        ) {
                            Ok(a) => a,
                            Err(e) => {
                                error!(err = %e, "invalid vault address in config");
                                return;
                            }
                        };

                        match watcher
                            .rpc
                            .send_release(
                                watcher.config.chain_id,
                                &vault_addr,
                                &params.token,
                                params.amount,
                                &params.recipient,
                                &params.bridge_id,
                                &event.ecdsa_sigs_sorted,
                                &self.ecdsa_key,
                            )
                            .await
                        {
                            Ok(tx_hash) => {
                                info!(
                                    tx = hex::encode(tx_hash),
                                    chain = %watcher.config.chain,
                                    "release transaction submitted"
                                );
                            }
                            Err(e) => {
                                error!(
                                    err = %e,
                                    chain = %watcher.config.chain,
                                    "release transaction failed"
                                );
                            }
                        }
                    } else {
                        warn!(op = hex::encode(event.op_id), "release threshold met but no params stored");
                    }
                }
            }
            OpType::Mint => {
                info!(
                    op = hex::encode(event.op_id),
                    "mint threshold met — submitting to Zero chain"
                );

                if let Err(e) = self.submit_mint_to_zero(&event.op_id, state).await {
                    error!(
                        op = hex::encode(event.op_id),
                        err = %e,
                        "failed to submit mint to Zero chain"
                    );
                }
            }
        }
    }

    /// Sign a release request and create an operation in the coordinator.
    /// Called when a burn event is detected on the Zero chain.
    pub async fn initiate_release(
        &self,
        params: &ReleaseParams,
        state: &Arc<AppState>,
        peer_endpoints: &[String],
    ) -> Result<(), anyhow::Error> {
        let signed = self.signer.sign_release(params)
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add to our own collector
        let mut collector = state.collector.lock().await;
        collector.create_operation(
            params.bridge_id,
            OpType::Release,
            Some(signed.digest),
            now,
        );
        collector.add_ecdsa_signature(&params.bridge_id, &signed.signature)
            .map_err(|e| anyhow::anyhow!("self-signature failed: {}", e))?;
        drop(collector);

        // Share with peers
        for endpoint in peer_endpoints {
            match http::send_ecdsa_to_peer(
                &self.http_client,
                endpoint,
                &params.bridge_id,
                &signed.signature,
            ).await {
                Ok(()) => info!(peer = %endpoint, "shared ECDSA signature"),
                Err(e) => warn!(peer = %endpoint, err = %e, "failed to share signature"),
            }
        }

        Ok(())
    }

    /// Submit a mint attestation to the Zero chain.
    /// Called when 2-of-3 Ed25519 signatures have been collected.
    /// Sends attestation data to the Zero chain node's mint API endpoint.
    async fn submit_mint_to_zero(
        &self,
        op_id: &[u8; 32],
        state: &Arc<AppState>,
    ) -> Result<(), anyhow::Error> {
        let collector = state.collector.lock().await;
        let pending = collector.get_operation(op_id)
            .ok_or_else(|| anyhow::anyhow!("operation not found for mint submission"))?;

        // Collect the Ed25519 attestation signatures
        let sigs: Vec<_> = pending.ed25519_signatures.iter()
            .map(|(pk, sig)| (hex::encode(pk), hex::encode(sig)))
            .collect();
        drop(collector);

        info!(
            op = hex::encode(op_id),
            attestations = sigs.len(),
            zero_rpc = %self.config.zero_rpc,
            "mint attestation ready — {} of 3 signatures collected",
            sigs.len(),
        );

        // The Zero chain node needs a mint attestation HTTP endpoint.
        // For now, log the successful collection. The chain node will be
        // extended with a POST /bridge/mint endpoint that accepts:
        //   { op_id, recipient, amount, source_chain, source_tx, signatures: [{pubkey, sig}] }
        // and calls executor.bridge_mint() after verifying the attestation
        // via TrinityValidatorSet::verify_attestation().

        Ok(())
    }

    /// Build the 3-guardian Ethereum address array from config.
    /// Our address goes at `trinity.index`, peers fill the remaining slots.
    fn guardians_from_config(&self) -> Result<[[u8; 20]; 3], anyhow::Error> {
        let my_index = self.config.trinity.index;
        if my_index >= 3 {
            return Err(anyhow::anyhow!("trinity.index must be 0, 1, or 2"));
        }
        if self.config.peers.len() != 2 {
            return Err(anyhow::anyhow!("expected exactly 2 peers, got {}", self.config.peers.len()));
        }

        let mut guardians = [[0u8; 20]; 3];
        guardians[my_index] = self.signer.address;

        let mut peer_idx = 0;
        for i in 0..3 {
            if i == my_index {
                continue;
            }
            let addr_hex = &self.config.peers[peer_idx].eth_address;
            let clean = addr_hex.strip_prefix("0x").unwrap_or(addr_hex);
            let bytes = hex::decode(clean)
                .map_err(|e| anyhow::anyhow!("invalid peer eth_address: {}", e))?;
            if bytes.len() != 20 {
                return Err(anyhow::anyhow!("peer eth_address must be 20 bytes"));
            }
            guardians[i].copy_from_slice(&bytes);
            peer_idx += 1;
        }

        Ok(guardians)
    }

    /// Build the 3-validator Ed25519 public key array from config.
    fn trinity_pubkeys_from_config(&self) -> Result<[[u8; 32]; 3], anyhow::Error> {
        let my_index = self.config.trinity.index;
        if self.config.peers.len() != 2 {
            return Err(anyhow::anyhow!("expected exactly 2 peers, got {}", self.config.peers.len()));
        }

        // Derive our own Ed25519 pubkey from the key file
        let ed_key_bytes = std::fs::read(&self.config.trinity.ed25519_key_file)
            .map_err(|e| anyhow::anyhow!("failed to read ed25519 key: {}", e))?;
        let ed_key: [u8; 32] = hex::decode(ed_key_bytes.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect::<Vec<u8>>())
            .map_err(|e| anyhow::anyhow!("invalid ed25519 key hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ed25519 key must be 32 bytes"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_key);
        let my_pubkey = signing_key.verifying_key().to_bytes();

        let mut pubkeys = [[0u8; 32]; 3];
        pubkeys[my_index] = my_pubkey;

        let mut peer_idx = 0;
        for i in 0..3 {
            if i == my_index {
                continue;
            }
            let pk_hex = &self.config.peers[peer_idx].ed25519_pubkey;
            let bytes = hex::decode(pk_hex)
                .map_err(|e| anyhow::anyhow!("invalid peer ed25519_pubkey: {}", e))?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!("peer ed25519_pubkey must be 32 bytes"));
            }
            pubkeys[i].copy_from_slice(&bytes);
            peer_idx += 1;
        }

        Ok(pubkeys)
    }
}
