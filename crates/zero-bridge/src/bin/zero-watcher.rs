//! Zero Vault Watcher — independent monitoring daemon.
//!
//! Runs separately from the bridge service. Watches vault contracts for
//! unusual activity and can pause the vault if an attack is detected.
//!
//! Key principle: the watcher has NO signing keys. It can only pause, never release.
//! This separation ensures a compromised bridge service cannot suppress alarms.
//!
//! Usage:
//!   zero-watcher --config watcher.json
//!   zero-watcher --config watcher.json --generate-config

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tracing::{error, info, warn};

use zero_bridge::config::BridgeConfig;
use zero_bridge::rpc::EthRpc;
use zero_bridge::watcher::{VaultWatcher, WatcherConfig};

/// Watcher-specific config wrapping the shared bridge config.
#[derive(serde::Deserialize, serde::Serialize)]
struct FullWatcherConfig {
    /// Shared bridge config (vaults, etc.)
    bridge: BridgeConfig,
    /// Watcher-specific settings
    watcher: WatcherSettings,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct WatcherSettings {
    /// Large release alert threshold (token units)
    large_release_threshold: u64,
    /// Rapid release count threshold
    rapid_release_count: usize,
    /// Rapid release window (seconds)
    rapid_window_secs: u64,
    /// Auto-pause on elevated tier?
    auto_pause_on_elevated: bool,
    /// Poll interval (milliseconds)
    poll_interval_ms: u64,
    /// ECDSA private key file for calling pause() (PAUSER_ROLE only)
    pause_key_file: String,
}

impl Default for WatcherSettings {
    fn default() -> Self {
        Self {
            large_release_threshold: 100_000_000, // 100 USDC
            rapid_release_count: 10,
            rapid_window_secs: 300,
            auto_pause_on_elevated: true,
            poll_interval_ms: 5000,
            pause_key_file: "watcher_pause.key".into(),
        }
    }
}

impl Default for FullWatcherConfig {
    fn default() -> Self {
        Self {
            bridge: BridgeConfig::default(),
            watcher: WatcherSettings::default(),
        }
    }
}

/// Load a 32-byte ECDSA private key from a hex-encoded file.
fn load_pause_key(path: &str) -> Result<[u8; 32], anyhow::Error> {
    let raw = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read pause key file '{}': {}", path, e))?;
    let hex_str: String = raw.iter().copied()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b as char)
        .collect();
    let bytes = hex::decode(&hex_str)
        .map_err(|e| anyhow::anyhow!("invalid pause key hex: {}", e))?;
    let key: [u8; 32] = bytes.try_into()
        .map_err(|_| anyhow::anyhow!("pause key must be 32 bytes"))?;
    Ok(key)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zero_watcher=info,zero_bridge=info,warn".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();

    let config_path = args.iter()
        .position(|a| a == "--config")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("watcher.json"));

    if args.iter().any(|a| a == "--generate-config") {
        let config = FullWatcherConfig::default();
        let json = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_path, &json)?;
        println!("Default watcher config written to {}", config_path.display());
        return Ok(());
    }

    let config_str = std::fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("failed to read config {}: {}", config_path.display(), e))?;
    let config: FullWatcherConfig = serde_json::from_str(&config_str)
        .map_err(|e| anyhow::anyhow!("failed to parse config: {}", e))?;

    info!(
        vaults = config.bridge.vaults.len(),
        large_threshold = config.watcher.large_release_threshold,
        auto_pause = config.watcher.auto_pause_on_elevated,
        "vault watcher starting"
    );

    let watcher_config = WatcherConfig {
        large_release_threshold: config.watcher.large_release_threshold,
        rapid_release_count: config.watcher.rapid_release_count,
        rapid_window_secs: config.watcher.rapid_window_secs,
        auto_pause_on_elevated: config.watcher.auto_pause_on_elevated,
        poll_interval_ms: config.watcher.poll_interval_ms,
    };

    let watcher = Arc::new(Mutex::new(VaultWatcher::new(watcher_config)));
    let poll_interval = Duration::from_millis(config.watcher.poll_interval_ms);

    // Initialize RPC clients for each vault
    let mut chain_states: Vec<(EthRpc, String, u64)> = Vec::new();
    for vault_config in &config.bridge.vaults {
        let rpc = EthRpc::new(&vault_config.rpc_url, &vault_config.chain);
        match rpc.block_number().await {
            Ok(block) => {
                info!(
                    chain = %vault_config.chain,
                    block,
                    vault = %vault_config.vault_address,
                    "watcher connected to chain"
                );
                chain_states.push((rpc, vault_config.vault_address.clone(), block));
            }
            Err(e) => {
                warn!(chain = %vault_config.chain, err = %e, "watcher failed to connect — will retry");
                chain_states.push((rpc, vault_config.vault_address.clone(), 0));
            }
        }
    }

    let mut poll = tokio::time::interval(poll_interval);
    poll.tick().await;

    // Status logging interval
    let mut status_interval = tokio::time::interval(Duration::from_secs(60));
    status_interval.tick().await;

    info!("vault watcher running — monitoring {} vault(s)", chain_states.len());

    loop {
        tokio::select! {
            _ = poll.tick() => {
                for (i, vault_config) in config.bridge.vaults.iter().enumerate() {
                    let (ref rpc, ref vault_addr, ref mut last_block) = chain_states[i];

                    let current_block = match rpc.block_number().await {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(chain = %vault_config.chain, err = %e, "watcher poll failed");
                            continue;
                        }
                    };

                    let safe_block = current_block.saturating_sub(vault_config.confirmations);
                    if safe_block <= *last_block {
                        continue;
                    }

                    // Fetch deposit logs
                    match rpc.get_deposit_logs(vault_addr, *last_block + 1, safe_block).await {
                        Ok(logs) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let mut w = watcher.lock().await;
                            for log in &logs {
                                if let Ok(deposit) = rpc.parse_deposit_log(log) {
                                    w.record_deposit(
                                        &hex::encode(deposit.token),
                                        deposit.amount,
                                        now,
                                    );
                                    info!(
                                        chain = %vault_config.chain,
                                        amount = deposit.amount,
                                        "watcher: deposit observed"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            warn!(chain = %vault_config.chain, err = %e, "watcher: failed to fetch deposit logs");
                        }
                    }

                    // Fetch Released events for anomaly detection
                    match rpc.get_release_logs(vault_addr, *last_block + 1, safe_block).await {
                        Ok(logs) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let mut w = watcher.lock().await;
                            for log in &logs {
                                if let Ok(release) = rpc.parse_release_log(log) {
                                    let alerts = w.record_release(
                                        &hex::encode(release.token),
                                        release.amount,
                                        &hex::encode(release.tx_hash),
                                        now,
                                    );
                                    info!(
                                        chain = %vault_config.chain,
                                        amount = release.amount,
                                        bridge_id = hex::encode(release.bridge_id),
                                        "watcher: release observed"
                                    );
                                    for (anomaly, action) in &alerts {
                                        warn!(
                                            chain = %vault_config.chain,
                                            anomaly = ?anomaly,
                                            action = ?action,
                                            "watcher: anomaly detected"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!(chain = %vault_config.chain, err = %e, "watcher: failed to fetch release logs");
                        }
                    }

                    *last_block = safe_block;
                }
            }

            _ = status_interval.tick() => {
                let w = watcher.lock().await;
                let anomaly_count = w.anomalies().len();
                let pause_count = w.pause_required_count();
                info!(
                    anomalies = anomaly_count,
                    pause_required = pause_count,
                    "watcher status"
                );
                if pause_count > 0 {
                    error!(
                        count = pause_count,
                        "PAUSE REQUIRED — anomalies detected that warrant vault pause"
                    );

                    // Load pause key and submit pause() transaction to each vault
                    match load_pause_key(&config.watcher.pause_key_file) {
                        Ok(pause_key) => {
                            for (i, vault_config) in config.bridge.vaults.iter().enumerate() {
                                let (ref rpc, _, _) = chain_states[i];
                                let vault_addr = match zero_bridge::config::BridgeConfig::vault_address_bytes(
                                    &vault_config.vault_address,
                                ) {
                                    Ok(a) => a,
                                    Err(e) => {
                                        error!(chain = %vault_config.chain, err = %e, "invalid vault address");
                                        continue;
                                    }
                                };

                                match rpc.send_pause(
                                    vault_config.chain_id,
                                    &vault_addr,
                                    &pause_key,
                                ).await {
                                    Ok(tx_hash) => {
                                        error!(
                                            chain = %vault_config.chain,
                                            tx = hex::encode(tx_hash),
                                            "VAULT PAUSED — pause transaction submitted"
                                        );
                                    }
                                    Err(e) => {
                                        error!(
                                            chain = %vault_config.chain,
                                            err = %e,
                                            "FAILED TO PAUSE VAULT"
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!(err = %e, "cannot pause: failed to load pause key");
                        }
                    }
                }
            }
        }
    }
}
