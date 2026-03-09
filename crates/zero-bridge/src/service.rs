//! Bridge service — the main event loop for a Trinity Validator.
//!
//! Orchestrates:
//!   1. Polling Ethereum RPC for new Deposited events (bridge-in)
//!   2. Signing deposits and sharing with peers (Ed25519 attestations)
//!   3. Signing release requests and sharing with peers (ECDSA / EIP-712)
//!   4. Executing operations when signature threshold is met
//!   5. Periodic cleanup of stale pending operations

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc};
use tracing::{error, info, warn};

use ed25519_dalek::{Signer, SigningKey};

use crate::config::{BridgeConfig, VaultConfig};
use crate::coordinator::{MintMeta, OpType, SignatureCollector};
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
    /// Per-chain EIP-712 signers, keyed by chain name (e.g. "base", "arbitrum").
    signers: HashMap<String, Eip712Signer>,
    ecdsa_key: [u8; 32],
    ed25519_signing_key: SigningKey,
    ed25519_pubkey: [u8; 32],
    /// Our Ethereum address (derived from ECDSA key, same across all chains).
    ecdsa_address: [u8; 20],
    http_client: reqwest::Client,
    /// Path to the block-height checkpoint file (persists last_block per chain).
    checkpoint_path: PathBuf,
}

impl BridgeService {
    /// Create a new bridge service from config.
    ///
    /// `config_path` is the path to the bridge JSON config file; the checkpoint
    /// file is placed alongside it with a `.checkpoint` suffix (e.g.
    /// `bridge.json` -> `bridge.json.checkpoint`).
    pub fn new(
        config: BridgeConfig,
        ecdsa_key: [u8; 32],
        config_path: &std::path::Path,
    ) -> Result<Self, anyhow::Error> {
        if config.vaults.is_empty() {
            return Err(anyhow::anyhow!("no vaults configured"));
        }

        // Build a per-chain EIP-712 signer for each vault deployment.
        let mut signers = HashMap::new();
        let mut ecdsa_address = [0u8; 20];
        for vault in &config.vaults {
            let vault_addr = BridgeConfig::vault_address_bytes(&vault.vault_address)?;
            let signer = Eip712Signer::new(&ecdsa_key, vault.chain_id, vault_addr)
                .map_err(|e| anyhow::anyhow!("failed to create signer for {}: {}", vault.chain, e))?;
            ecdsa_address = signer.address;
            info!(
                chain = %vault.chain,
                chain_id = vault.chain_id,
                vault = %vault.vault_address,
                address = hex::encode(signer.address),
                "EIP-712 signer created for chain"
            );
            signers.insert(vault.chain.clone(), signer);
        }

        // Load Ed25519 signing key for Zero chain attestations
        let ed_key_bytes = std::fs::read(&config.trinity.ed25519_key_file)
            .map_err(|e| anyhow::anyhow!("failed to read ed25519 key: {}", e))?;
        let ed_key: [u8; 32] = hex::decode(
            ed_key_bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>(),
        )
        .map_err(|e| anyhow::anyhow!("invalid ed25519 key hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 key must be 32 bytes"))?;
        let ed25519_signing_key = SigningKey::from_bytes(&ed_key);
        let ed25519_pubkey = ed25519_signing_key.verifying_key().to_bytes();

        // Derive checkpoint path: <config_path>.checkpoint
        let checkpoint_path = {
            let mut p = config_path.to_path_buf();
            let mut name = p
                .file_name()
                .unwrap_or_default()
                .to_os_string();
            name.push(".checkpoint");
            p.set_file_name(name);
            p
        };

        info!(
            address = hex::encode(ecdsa_address),
            ed25519_pubkey = hex::encode(ed25519_pubkey),
            chains = signers.len(),
            checkpoint = %checkpoint_path.display(),
            "Trinity Validator initialized (ECDSA + Ed25519)"
        );

        Ok(Self {
            config,
            signers,
            ecdsa_key,
            ed25519_signing_key,
            ed25519_pubkey,
            ecdsa_address,
            http_client: reqwest::Client::new(),
            checkpoint_path,
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
            stats: http::BridgeStats::new(),
            submitted_ops: Mutex::new(std::collections::HashSet::new()),
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

        // Load block-height checkpoint (if any) so we resume from where we left off.
        let checkpoint = self.load_checkpoint();

        // Initialize per-chain watchers
        let mut watchers: Vec<ChainWatcher> = Vec::new();
        for vault_config in &self.config.vaults {
            let rpc = EthRpc::new(&vault_config.rpc_url, &vault_config.chain);

            // Prefer the checkpointed block over the live tip so we don't skip
            // deposits that arrived while the bridge was down.
            let start_block = if let Some(&saved) = checkpoint.get(&vault_config.chain) {
                info!(
                    chain = %vault_config.chain,
                    saved_block = saved,
                    vault = %vault_config.vault_address,
                    "resuming from checkpoint"
                );
                saved
            } else {
                // No checkpoint — fall back to current block (original behaviour).
                match rpc.block_number().await {
                    Ok(block) => {
                        info!(
                            chain = %vault_config.chain,
                            block,
                            vault = %vault_config.vault_address,
                            "connected to chain (no checkpoint, starting at tip)"
                        );
                        block
                    }
                    Err(e) => {
                        warn!(
                            chain = %vault_config.chain,
                            err = %e,
                            "failed to connect — will retry"
                        );
                        0
                    }
                }
            };

            watchers.push(ChainWatcher {
                config: vault_config.clone(),
                rpc,
                last_block: start_block,
            });
        }

        let peer_endpoints: Vec<String> = self
            .config
            .peers
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

        // Release poll interval — check for pending burns every 2 seconds
        let mut release_poll = tokio::time::interval(Duration::from_secs(2));
        release_poll.tick().await;

        loop {
            tokio::select! {
                // Poll chains for new deposits
                _ = poll.tick() => {
                    let mut any_advanced = false;
                    for watcher in &mut watchers {
                        let prev = watcher.last_block;
                        if let Err(e) = self.poll_chain(watcher, &state).await {
                            warn!(
                                chain = %watcher.config.chain,
                                err = %e,
                                "poll error"
                            );
                        }
                        if watcher.last_block > prev {
                            any_advanced = true;
                        }
                    }
                    // Persist checkpoint only when at least one chain advanced.
                    if any_advanced {
                        self.save_checkpoint(&watchers);
                    }
                }

                // Poll Zero chain node for pending release operations (burns)
                // and sign any releases received from peers
                _ = release_poll.tick() => {
                    if let Err(e) = self.poll_pending_releases(&state, &peer_endpoints, &watchers).await {
                        warn!(err = %e, "release poll error");
                    }
                    self.sign_pending_releases(&state, &peer_endpoints).await;
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

        // Record poll stats for health endpoint
        state.stats.record_poll(&watcher.config.chain, current_block).await;

        // Need enough confirmations
        let safe_block = current_block.saturating_sub(watcher.config.confirmations);
        if safe_block <= watcher.last_block {
            return Ok(()); // No new confirmed blocks
        }

        let logs = watcher
            .rpc
            .get_deposit_logs(
                &watcher.config.vault_address,
                watcher.last_block + 1,
                safe_block,
            )
            .await?;

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

                    // Convert to Z units and prepare signing data
                    let z_units = deposit.to_z_units(watcher.config.token_decimals);
                    let source_tx_hex = hex::encode(deposit.source_tx);

                    let mut collector = state.collector.lock().await;
                    collector.create_operation(op_id, OpType::Mint, None, now);

                    // Store deposit details so submit_mint_to_zero() can build the POST body
                    collector.set_mint_meta(
                        &op_id,
                        MintMeta {
                            recipient: deposit.zero_recipient,
                            amount: z_units,
                            source_chain: deposit.source_chain.clone(),
                            source_tx: source_tx_hex.clone(),
                        },
                    );

                    // Sign the mint attestation with our Ed25519 key
                    let mint_op = BridgeOp::Mint {
                        recipient: deposit.zero_recipient,
                        amount: z_units,
                        source_chain: deposit.source_chain.clone(),
                        source_tx: source_tx_hex.clone(),
                    };
                    let signing_bytes = mint_op.signing_bytes();
                    let signature = self.ed25519_signing_key.sign(&signing_bytes);
                    let sig_bytes = signature.to_bytes();

                    // Add our own signature to the collector
                    match collector.add_ed25519_signature(&op_id, &self.ed25519_pubkey, &sig_bytes)
                    {
                        Ok(_) => {
                            info!(
                                op = hex::encode(op_id),
                                z_units, "signed mint attestation (Ed25519)"
                            );
                        }
                        Err(e) => {
                            warn!(op = hex::encode(op_id), err = %e, "failed to add own Ed25519 signature");
                        }
                    }
                    drop(collector);

                    // Share our Ed25519 signature with peers
                    let peer_endpoints: Vec<String> = self
                        .config
                        .peers
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
                        )
                        .await
                        {
                            Ok(()) => info!(peer = %endpoint, "shared Ed25519 mint attestation"),
                            Err(e) => {
                                let err_msg = e.to_string();
                                if err_msg.contains("operation not found") {
                                    info!(
                                        peer = %endpoint,
                                        "peer has not detected deposit yet, retrying in 3s"
                                    );
                                    tokio::time::sleep(Duration::from_secs(3)).await;
                                    match http::send_ed25519_to_peer(
                                        &self.http_client,
                                        endpoint,
                                        &op_id,
                                        &self.ed25519_pubkey,
                                        &sig_bytes,
                                    )
                                    .await
                                    {
                                        Ok(()) => info!(
                                            peer = %endpoint,
                                            "shared Ed25519 mint attestation (retry succeeded)"
                                        ),
                                        Err(e2) => warn!(
                                            peer = %endpoint,
                                            err = %e2,
                                            "failed to share mint attestation after retry"
                                        ),
                                    }
                                } else {
                                    warn!(
                                        peer = %endpoint,
                                        err = %e,
                                        "failed to share mint attestation"
                                    );
                                }
                            }
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

    /// Persist current `last_block` for every watcher to the checkpoint file.
    fn save_checkpoint(&self, watchers: &[ChainWatcher]) {
        let map: HashMap<&str, u64> = watchers
            .iter()
            .map(|w| (w.config.chain.as_str(), w.last_block))
            .collect();
        match serde_json::to_string_pretty(&map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.checkpoint_path, json.as_bytes()) {
                    warn!(
                        path = %self.checkpoint_path.display(),
                        err = %e,
                        "failed to write checkpoint file"
                    );
                }
            }
            Err(e) => {
                warn!(err = %e, "failed to serialize checkpoint");
            }
        }
    }

    /// Load the block-height checkpoint from disk.
    ///
    /// Returns an empty map if the file doesn't exist or can't be parsed, so
    /// callers can fall back to the current block height.
    fn load_checkpoint(&self) -> HashMap<String, u64> {
        match std::fs::read_to_string(&self.checkpoint_path) {
            Ok(contents) => match serde_json::from_str::<HashMap<String, u64>>(&contents) {
                Ok(map) => {
                    info!(
                        path = %self.checkpoint_path.display(),
                        chains = map.len(),
                        "loaded block checkpoint"
                    );
                    map
                }
                Err(e) => {
                    warn!(
                        path = %self.checkpoint_path.display(),
                        err = %e,
                        "checkpoint file exists but failed to parse — starting fresh"
                    );
                    HashMap::new()
                }
            },
            Err(_) => {
                info!(
                    path = %self.checkpoint_path.display(),
                    "no checkpoint file found — will start from chain tip"
                );
                HashMap::new()
            }
        }
    }

    /// Handle an operation that has reached signature threshold.
    async fn handle_threshold_met(
        &self,
        event: ThresholdEvent,
        _peer_endpoints: &[String],
        watchers: &[ChainWatcher],
        state: &Arc<AppState>,
    ) {
        // Deduplicate: skip if we already submitted this operation on-chain.
        {
            let submitted = state.submitted_ops.lock().await;
            if submitted.contains(&event.op_id) {
                info!(
                    op = hex::encode(event.op_id),
                    "skipping duplicate threshold event (already submitted)"
                );
                return;
            }
        }

        match event.op_type {
            OpType::Release => {
                info!(
                    op = hex::encode(event.op_id),
                    sigs_len = event.ecdsa_sigs_sorted.len(),
                    "release threshold met — submitting to vault"
                );

                if let Some(params) = &event.release_params {
                    // Route to the vault whose chain matches the burn's dest_chain.
                    let watcher = watchers
                        .iter()
                        .find(|w| w.config.chain == params.dest_chain);

                    let watcher = match watcher {
                        Some(w) => w,
                        None => {
                            error!(
                                op = hex::encode(event.op_id),
                                dest_chain = %params.dest_chain,
                                "no vault configured for destination chain"
                            );
                            return;
                        }
                    };

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
                            state.stats.record_completion(&OpType::Release);
                            state.submitted_ops.lock().await.insert(event.op_id);

                            // Notify the Zero chain node that release is complete
                            let complete_url = format!(
                                "{}/bridge/release_complete",
                                self.config.zero_rpc
                            );
                            let _ = self
                                .http_client
                                .post(&complete_url)
                                .json(&serde_json::json!({
                                    "bridge_id": hex::encode(event.op_id),
                                }))
                                .timeout(Duration::from_secs(5))
                                .send()
                                .await;
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
                    warn!(
                        op = hex::encode(event.op_id),
                        "release threshold met but no params stored"
                    );
                }
            }
            OpType::Mint => {
                info!(
                    op = hex::encode(event.op_id),
                    "mint threshold met — submitting to Zero chain"
                );

                match self.submit_mint_to_zero(&event.op_id, state).await {
                    Ok(()) => {
                        state.stats.record_completion(&OpType::Mint);
                        state.submitted_ops.lock().await.insert(event.op_id);
                    }
                    Err(e) => {
                        error!(
                            op = hex::encode(event.op_id),
                            err = %e,
                            "failed to submit mint to Zero chain"
                        );
                    }
                }
            }
        }
    }

    /// Poll the Zero chain node for pending release operations (bridge-out burns).
    async fn poll_pending_releases(
        &self,
        state: &Arc<AppState>,
        peer_endpoints: &[String],
        watchers: &[ChainWatcher],
    ) -> Result<(), anyhow::Error> {
        let url = format!("{}/bridge/pending_releases", self.config.zero_rpc);
        let resp = self
            .http_client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(());
        }

        let ops: Vec<serde_json::Value> = resp.json().await?;
        if ops.is_empty() {
            return Ok(());
        }

        for op in &ops {
            let bridge_id_hex = op["bridge_id"].as_str().unwrap_or("");
            let dest_chain = op["source_chain"].as_str().unwrap_or(""); // stored as source_chain for bridge-out
            let token_sym = op["token"].as_str().unwrap_or("USDC");
            let z_amount = op["z_amount"].as_u64().unwrap_or(0) as u32;
            let dest_address = op["dest_address"].as_str().unwrap_or("");

            if bridge_id_hex.is_empty() || dest_chain.is_empty() || dest_address.is_empty() {
                continue;
            }

            // Check if we already have this operation in our collector
            {
                let collector = state.collector.lock().await;
                let op_id_bytes: [u8; 32] = match hex::decode(bridge_id_hex) {
                    Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                    _ => continue,
                };
                if collector.get_operation(&op_id_bytes).is_some() {
                    continue; // Already processing this one
                }
            }

            // Find the vault config for this chain to get token address and decimals
            let vault = watchers.iter().find(|w| w.config.chain == dest_chain);
            let vault = match vault {
                Some(w) => &w.config,
                None => {
                    warn!(chain = dest_chain, "no vault for release destination");
                    continue;
                }
            };

            // Parse the dest_address (Ethereum address)
            let addr_clean = dest_address.strip_prefix("0x").unwrap_or(dest_address);
            let recipient: [u8; 20] = match hex::decode(addr_clean) {
                Ok(b) if b.len() == 20 => b.try_into().unwrap(),
                _ => {
                    warn!(addr = dest_address, "invalid dest_address");
                    continue;
                }
            };

            // Parse token address from vault config
            let token_clean = vault.token_address.strip_prefix("0x").unwrap_or(&vault.token_address);
            let token: [u8; 20] = match hex::decode(token_clean) {
                Ok(b) if b.len() == 20 => b.try_into().unwrap(),
                _ => {
                    warn!(token = %vault.token_address, "invalid token address");
                    continue;
                }
            };

            // Convert Z units to raw token amount
            // z_amount is in Z units (1 Z = 100 units), token has `token_decimals` decimals
            // 10,000 Z units = 1 USDC = 10^6 raw
            // raw = z_amount * 10^decimals / 10000
            let raw_amount = (z_amount as u64)
                * 10u64.pow(vault.token_decimals as u32)
                / 10_000;

            // Parse bridge_id to 32 bytes
            let bridge_id: [u8; 32] = match hex::decode(bridge_id_hex) {
                Ok(b) if b.len() == 32 => b.try_into().unwrap(),
                _ => continue,
            };

            let params = ReleaseParams {
                token,
                amount: raw_amount,
                recipient,
                bridge_id,
                dest_chain: dest_chain.to_string(),
            };

            info!(
                bridge_id = bridge_id_hex,
                chain = dest_chain,
                token = token_sym,
                z_amount,
                raw_amount,
                recipient = hex::encode(recipient),
                "detected pending release — initiating ECDSA signing"
            );

            if let Err(e) = self.initiate_release(&params, state, peer_endpoints).await {
                error!(
                    bridge_id = bridge_id_hex,
                    err = %e,
                    "failed to initiate release"
                );
            }
        }

        Ok(())
    }

    /// Sign a release request and create an operation in the coordinator.
    /// Called when a burn event is detected on the Zero chain.
    pub async fn initiate_release(
        &self,
        params: &ReleaseParams,
        state: &Arc<AppState>,
        peer_endpoints: &[String],
    ) -> Result<(), anyhow::Error> {
        let signer = self
            .signers
            .get(&params.dest_chain)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no EIP-712 signer for chain '{}' — check vault config",
                    params.dest_chain
                )
            })?;
        let signed = signer
            .sign_release(params)
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Add to our own collector
        let mut collector = state.collector.lock().await;
        collector.create_operation(params.bridge_id, OpType::Release, Some(signed.digest), now);
        collector.set_release_params(&params.bridge_id, params.clone());
        collector
            .add_ecdsa_signature(&params.bridge_id, &signed.signature)
            .map_err(|e| anyhow::anyhow!("self-signature failed: {}", e))?;
        drop(collector);

        // Share with peers (include release params + digest so they can auto-create the operation)
        for endpoint in peer_endpoints {
            match http::send_ecdsa_to_peer(
                &self.http_client,
                endpoint,
                &params.bridge_id,
                &signed.signature,
                Some(params),
                Some(&signed.digest),
            )
            .await
            {
                Ok(()) => info!(peer = %endpoint, "shared ECDSA release signature + params"),
                Err(e) => warn!(peer = %endpoint, err = %e, "failed to share release signature"),
            }
        }

        Ok(())
    }

    /// Check the coordinator for release operations that we haven't signed yet
    /// (auto-created from peer params) and sign them.
    async fn sign_pending_releases(
        &self,
        state: &Arc<AppState>,
        peer_endpoints: &[String],
    ) {
        let unsigned = {
            let collector = state.collector.lock().await;
            collector.unsigned_releases(&self.ecdsa_address)
        };

        for op_id in unsigned {
            // Get the release params
            let params = {
                let collector = state.collector.lock().await;
                collector
                    .get_operation(&op_id)
                    .and_then(|op| op.release_params.clone())
            };

            let params = match params {
                Some(p) => p,
                None => continue,
            };

            info!(
                op = hex::encode(op_id),
                chain = %params.dest_chain,
                "signing release from peer (auto-sign)"
            );

            if let Err(e) = self.initiate_release(&params, state, peer_endpoints).await {
                warn!(
                    op = hex::encode(op_id),
                    err = %e,
                    "failed to auto-sign release"
                );
            }
        }
    }

    /// Submit a mint attestation to the Zero chain.
    /// Called when 2-of-3 Ed25519 signatures have been collected.
    /// POSTs attestation data to the Zero chain node's /bridge/mint endpoint.
    async fn submit_mint_to_zero(
        &self,
        op_id: &[u8; 32],
        state: &Arc<AppState>,
    ) -> Result<(), anyhow::Error> {
        let collector = state.collector.lock().await;
        let pending = collector
            .get_operation(op_id)
            .ok_or_else(|| anyhow::anyhow!("operation not found for mint submission"))?;

        let mint_meta = pending
            .mint_meta
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no mint metadata stored for operation"))?;

        // Build the JSON payload matching bridge_api.rs MintRequest
        let attestations: Vec<serde_json::Value> = pending
            .ed25519_signatures
            .iter()
            .map(|(pk, sig)| {
                serde_json::json!({
                    "pubkey": hex::encode(pk),
                    "signature": hex::encode(sig),
                })
            })
            .collect();

        let payload = serde_json::json!({
            "recipient": hex::encode(mint_meta.recipient),
            "amount": mint_meta.amount,
            "source_chain": mint_meta.source_chain,
            "source_tx": mint_meta.source_tx,
            "attestations": attestations,
        });

        let sigs_count = attestations.len();
        drop(collector);

        let url = format!("{}/bridge/mint", self.config.zero_rpc);
        info!(
            op = hex::encode(op_id),
            attestations = sigs_count,
            url = %url,
            "submitting mint to Zero chain"
        );

        let resp = self
            .http_client
            .post(&url)
            .json(&payload)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to reach Zero chain: {}", e))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if status.is_success() {
            info!(
                op = hex::encode(op_id),
                response = %body,
                "mint submitted successfully"
            );
            // Clean up the completed operation
            let mut collector = state.collector.lock().await;
            collector.remove_operation(op_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "mint submission failed ({}): {}",
                status,
                body
            ))
        }
    }

    /// Build the 3-guardian Ethereum address array from config.
    /// Our address goes at `trinity.index`, peers fill the remaining slots.
    fn guardians_from_config(&self) -> Result<[[u8; 20]; 3], anyhow::Error> {
        let my_index = self.config.trinity.index;
        if my_index >= 3 {
            return Err(anyhow::anyhow!("trinity.index must be 0, 1, or 2"));
        }
        if self.config.peers.len() != 2 {
            return Err(anyhow::anyhow!(
                "expected exactly 2 peers, got {}",
                self.config.peers.len()
            ));
        }

        let mut guardians = [[0u8; 20]; 3];
        guardians[my_index] = self.ecdsa_address;

        let mut peer_idx = 0;
        for (i, guardian) in guardians.iter_mut().enumerate() {
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
            guardian.copy_from_slice(&bytes);
            peer_idx += 1;
        }

        Ok(guardians)
    }

    /// Build the 3-validator Ed25519 public key array from config.
    fn trinity_pubkeys_from_config(&self) -> Result<[[u8; 32]; 3], anyhow::Error> {
        let my_index = self.config.trinity.index;
        if self.config.peers.len() != 2 {
            return Err(anyhow::anyhow!(
                "expected exactly 2 peers, got {}",
                self.config.peers.len()
            ));
        }

        // Derive our own Ed25519 pubkey from the key file
        let ed_key_bytes = std::fs::read(&self.config.trinity.ed25519_key_file)
            .map_err(|e| anyhow::anyhow!("failed to read ed25519 key: {}", e))?;
        let ed_key: [u8; 32] = hex::decode(
            ed_key_bytes
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>(),
        )
        .map_err(|e| anyhow::anyhow!("invalid ed25519 key hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed25519 key must be 32 bytes"))?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&ed_key);
        let my_pubkey = signing_key.verifying_key().to_bytes();

        let mut pubkeys = [[0u8; 32]; 3];
        pubkeys[my_index] = my_pubkey;

        let mut peer_idx = 0;
        for (i, pubkey) in pubkeys.iter_mut().enumerate() {
            if i == my_index {
                continue;
            }
            let pk_hex = &self.config.peers[peer_idx].ed25519_pubkey;
            let bytes = hex::decode(pk_hex)
                .map_err(|e| anyhow::anyhow!("invalid peer ed25519_pubkey: {}", e))?;
            if bytes.len() != 32 {
                return Err(anyhow::anyhow!("peer ed25519_pubkey must be 32 bytes"));
            }
            pubkey.copy_from_slice(&bytes);
            peer_idx += 1;
        }

        Ok(pubkeys)
    }
}
