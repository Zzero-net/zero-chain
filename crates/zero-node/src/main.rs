mod bridge_api;
mod faucet;

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::RwLock;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tracing::{error, info, warn};

use zero_consensus::{
    committee::ValidatorInfo, event_loop, event_loop::Broadcaster, Committee, Node,
    NodeGossipHandler,
};
use zero_crypto::keyfile;
use zero_network::{
    gossip::{GossipClient, GossipServer, GossipTlsConfig},
    proto::{zero_gossip_server::ZeroGossipServer, zero_service_server::ZeroServiceServer},
    server::ZeroServer,
};
use zero_storage::snapshot;
use zero_types::{block::Event, GenesisConfig, NodeConfig, Transfer};

/// Newtype wrapper to implement Broadcaster for GossipClient (orphan rule).
struct GossipBroadcaster(GossipClient);

impl Broadcaster for GossipBroadcaster {
    async fn broadcast(&self, event: &Event, transfers: &[Transfer]) -> (usize, usize) {
        self.0.broadcast(event, transfers).await
    }

    async fn pull_catchup(&self, from_round: u32, max_events: u32) -> Vec<(Event, Vec<Transfer>)> {
        self.0.pull_catchup(from_round, max_events).await
    }

    fn peer_count(&self) -> usize {
        self.0.peer_count()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Determine config path
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "zero.toml".into());

    let config_str = std::fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config {}: {}", config_path, e))?;

    let config = NodeConfig::from_toml(&config_str)
        .map_err(|e| anyhow::anyhow!("Invalid config: {}", e))?;

    info!(
        listen = config.listen,
        index = config.validator_index,
        peers = config.peers.len(),
        "Loaded node config"
    );

    // Load genesis
    let genesis_path = PathBuf::from(&config.data_dir).join("genesis.toml");
    let genesis_str = std::fs::read_to_string(&genesis_path)
        .map_err(|e| anyhow::anyhow!("Failed to read genesis {}: {}", genesis_path.display(), e))?;

    let genesis = GenesisConfig::from_toml(&genesis_str)
        .map_err(|e| anyhow::anyhow!("Invalid genesis: {}", e))?;

    info!(
        network = genesis.network,
        validators = genesis.validators.len(),
        accounts = genesis.accounts.len(),
        "Loaded genesis"
    );

    // Load validator keypair
    let keypair = keyfile::load(std::path::Path::new(&config.key_file))
        .map_err(|e| anyhow::anyhow!("Failed to load key: {}", e))?;

    let my_pubkey_hex = hex::encode(keypair.public_key());
    info!(pubkey = my_pubkey_hex, "Loaded validator key");

    // Build committee from genesis
    let validators: Vec<ValidatorInfo> = genesis
        .validators
        .iter()
        .enumerate()
        .map(|(i, gv)| {
            let pk_bytes: [u8; 32] = hex::decode(&gv.public_key)
                .expect("Invalid hex in genesis validator public_key")
                .try_into()
                .expect("Genesis validator public_key must be 32 bytes");
            ValidatorInfo {
                index: i as u16,
                public_key: pk_bytes,
                stake: gv.stake,
            }
        })
        .collect();

    let committee = Arc::new(Committee::new(validators));

    // Create node
    let node = Arc::new(RwLock::new(Node::new(
        config.validator_index,
        Arc::clone(&committee),
        config.log_capacity,
        config.max_batch_size,
    )));

    // Try to load snapshot
    let snapshot_dir = PathBuf::from(&config.data_dir);
    std::fs::create_dir_all(&snapshot_dir)?;
    let snapshot_path = snapshot_dir.join("state.snapshot");

    if snapshot_path.exists() {
        match snapshot::load_snapshot(&snapshot_path) {
            Ok((store, total_written)) => {
                info!(
                    accounts = store.len(),
                    total_written,
                    "Restored from snapshot"
                );
                // Replace the executor's account store with loaded data
                let n = node.read();
                let exec = n.executor().read();
                for (pk, acct) in store.iter_accounts() {
                    exec.accounts().set(pk, acct);
                }
            }
            Err(e) => {
                warn!(err = e, "Failed to load snapshot, starting fresh");
            }
        }
    }

    // Apply genesis pre-funded accounts
    {
        let n = node.read();
        let exec = n.executor().read();
        for ga in &genesis.accounts {
            let pk: [u8; 32] = hex::decode(&ga.public_key)
                .expect("Invalid hex in genesis account public_key")
                .try_into()
                .expect("Genesis account public_key must be 32 bytes");
            // Only mint if account doesn't already exist (from snapshot)
            if exec.accounts().balance(&pk) == 0 {
                exec.accounts().mint(&pk, ga.balance);
                info!(
                    account = &ga.public_key[..16],
                    balance = ga.balance,
                    "Genesis: funded account"
                );
            }
        }
    }

    // Client API server
    let api_server = ZeroServer::new(
        Arc::clone(&node),
        Arc::clone(node.read().executor()),
        config.peers.len() as u32,
    );

    // Load TLS config if specified
    let tls_config = if let (Some(cert_path), Some(key_path), Some(ca_path)) =
        (&config.tls_cert, &config.tls_key, &config.tls_ca)
    {
        let cert = std::fs::read(cert_path)
            .map_err(|e| anyhow::anyhow!("Failed to read TLS cert {}: {}", cert_path, e))?;
        let key = std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read TLS key {}: {}", key_path, e))?;
        let ca = std::fs::read(ca_path)
            .map_err(|e| anyhow::anyhow!("Failed to read TLS CA {}: {}", ca_path, e))?;
        info!("TLS enabled — mutual authentication active");
        Some((cert, key, ca))
    } else {
        None
    };

    // Gossip
    let gossip_handler = Arc::new(NodeGossipHandler::new(Arc::clone(&node)));
    let gossip_server = GossipServer::new(gossip_handler);
    let gossip_client = if let Some((ref cert, ref key, ref ca)) = tls_config {
        let tls = GossipTlsConfig {
            client_identity: Identity::from_pem(cert.clone(), key.clone()),
            ca_certificate: Certificate::from_pem(ca.clone()),
        };
        Arc::new(GossipBroadcaster(GossipClient::with_tls(
            config.peers.clone(),
            tls,
        )))
    } else {
        Arc::new(GossipBroadcaster(GossipClient::new(config.peers.clone())))
    };

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start consensus event loop
    let event_node = Arc::clone(&node);
    let event_gossip = Arc::clone(&gossip_client);
    let event_interval = config.event_interval_ms;
    tokio::spawn(async move {
        event_loop::run_event_loop(event_node, event_gossip, event_interval, shutdown_rx).await;
    });

    // Start faucet API if configured
    if let (Some(faucet_key_path), Some(faucet_listen)) =
        (&config.faucet_key, &config.faucet_listen)
    {
        match keyfile::load(std::path::Path::new(faucet_key_path)) {
            Ok(faucet_keypair) => {
                faucet::start_faucet(
                    Arc::clone(&node),
                    faucet_keypair,
                    faucet_listen.clone(),
                    config.faucet_amount,
                    config.faucet_cooldown_secs,
                );
            }
            Err(e) => {
                warn!(err = e, "Failed to load faucet key — faucet disabled");
            }
        }
    }

    // Start bridge mint API if configured
    if let Some(bridge_listen) = &config.bridge_listen {
        let trinity_pubkeys: Vec<[u8; 32]> = genesis
            .validators
            .iter()
            .map(|gv| {
                hex::decode(&gv.public_key)
                    .expect("Invalid hex in genesis validator public_key")
                    .try_into()
                    .expect("Genesis validator public_key must be 32 bytes")
            })
            .collect();

        bridge_api::start_bridge_api(
            Arc::clone(&node),
            trinity_pubkeys,
            bridge_listen.clone(),
        );
    }

    // Start periodic snapshot saving
    let snap_node = Arc::clone(&node);
    let snap_path = snapshot_path.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let n = snap_node.read();
            let exec = n.executor().read();
            if let Err(e) = snapshot::save_snapshot(
                exec.accounts(),
                exec.transfer_log().total_written(),
                &snap_path,
            ) {
                error!(err = %e, "Failed to save snapshot");
            }
        }
    });

    let addr = config.listen.parse()?;
    info!("Starting gRPC server on {}", addr);

    // Handle ctrl-c for graceful shutdown
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal");
        let _ = shutdown_tx_clone.send(true);
    });

    let mut builder = Server::builder();
    if let Some((cert, key, ca)) = tls_config {
        let server_tls = ServerTlsConfig::new()
            .identity(Identity::from_pem(cert, key))
            .client_ca_root(Certificate::from_pem(ca));
        builder = builder
            .tls_config(server_tls)
            .map_err(|e| anyhow::anyhow!("Server TLS config error: {}", e))?;
    }
    builder
        .add_service(ZeroServiceServer::new(api_server))
        .add_service(ZeroGossipServer::new(gossip_server))
        .serve_with_shutdown(addr, async move {
            let mut rx = shutdown_tx.subscribe();
            rx.changed().await.ok();
        })
        .await?;

    // Final snapshot before exit
    {
        let n = node.read();
        let exec = n.executor().read();
        if let Err(e) = snapshot::save_snapshot(
            exec.accounts(),
            exec.transfer_log().total_written(),
            &snapshot_path,
        ) {
            error!(err = %e, "Failed to save final snapshot");
        }
    }

    info!("Zero node stopped");
    Ok(())
}
