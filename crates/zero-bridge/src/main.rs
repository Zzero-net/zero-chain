//! Zero Bridge Attestation Service — Trinity Validator daemon.
//!
//! Usage:
//!   zero-bridge --config bridge.json
//!   zero-bridge --config bridge.json --generate-config  (write default config)

use std::path::PathBuf;

use anyhow::Context;
use tracing::info;

use zero_bridge::config::BridgeConfig;
use zero_bridge::service::BridgeService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zero_bridge=info,warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    // Parse simple CLI args
    let config_path = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bridge.json"));

    // Generate default config and exit
    if args.iter().any(|a| a == "--generate-config") {
        let config = BridgeConfig::default();
        let json = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_path, &json)?;
        println!("Default config written to {}", config_path.display());
        return Ok(());
    }

    // Load config
    let config_str = std::fs::read_to_string(&config_path)
        .with_context(|| format!("failed to read config: {}", config_path.display()))?;
    let config: BridgeConfig =
        serde_json::from_str(&config_str).with_context(|| "failed to parse config")?;

    info!(
        vaults = config.vaults.len(),
        peers = config.peers.len(),
        listen = %config.listen_addr,
        "loaded bridge config"
    );

    // Load ECDSA private key
    let key_path = &config.trinity.ecdsa_key_file;
    let key_hex = std::fs::read_to_string(key_path)
        .with_context(|| format!("failed to read ECDSA key: {}", key_path))?;
    let key_bytes = hex::decode(key_hex.trim())
        .with_context(|| "ECDSA key file must contain 64 hex characters")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("ECDSA key must be 32 bytes, got {}", key_bytes.len());
    }
    let mut ecdsa_key = [0u8; 32];
    ecdsa_key.copy_from_slice(&key_bytes);

    // Start the bridge service
    let service = BridgeService::new(config, ecdsa_key)?;
    service.run().await
}
