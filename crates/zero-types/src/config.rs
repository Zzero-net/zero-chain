use serde::{Deserialize, Serialize};

/// Node configuration loaded from zero.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's validator index (assigned from genesis).
    pub validator_index: u16,
    /// Path to the Ed25519 secret key file.
    pub key_file: String,
    /// gRPC listen address for client API + gossip.
    pub listen: String,
    /// Peer validator gRPC addresses.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Transfer log capacity (number of transfers in ring buffer).
    #[serde(default = "default_log_capacity")]
    pub log_capacity: usize,
    /// Max transfers per consensus event.
    #[serde(default = "default_max_batch")]
    pub max_batch_size: usize,
    /// Consensus event production interval in milliseconds.
    #[serde(default = "default_event_interval_ms")]
    pub event_interval_ms: u64,
    /// Path to state snapshot directory.
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    /// TLS certificate file (PEM). When set, enables mTLS on gossip.
    #[serde(default)]
    pub tls_cert: Option<String>,
    /// TLS private key file (PEM).
    #[serde(default)]
    pub tls_key: Option<String>,
    /// TLS CA certificate file (PEM) for verifying peers.
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// Faucet key file path. When set, enables the testnet faucet HTTP API.
    #[serde(default)]
    pub faucet_key: Option<String>,
    /// Faucet HTTP listen address (e.g. "0.0.0.0:8093").
    #[serde(default)]
    pub faucet_listen: Option<String>,
    /// Faucet drip amount in units per request (default: 10000 = 100 Z).
    #[serde(default = "default_faucet_amount")]
    pub faucet_amount: u32,
    /// Faucet cooldown per account in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_faucet_cooldown")]
    pub faucet_cooldown_secs: u64,
}

fn default_log_capacity() -> usize {
    1_000_000
}
fn default_max_batch() -> usize {
    1000
}
fn default_event_interval_ms() -> u64 {
    100
}
fn default_data_dir() -> String {
    "data".into()
}
fn default_faucet_amount() -> u32 {
    2_500 // 25 Z = $0.25 (MAX_TRANSFER_AMOUNT)
}
fn default_faucet_cooldown() -> u64 {
    3600 // 1 hour
}

/// Genesis configuration — defines the initial state of the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Network name (e.g. "zero-devnet", "zero-testnet", "zero-mainnet").
    pub network: String,
    /// Initial validator set.
    pub validators: Vec<GenesisValidator>,
    /// Pre-funded accounts (for testing / faucet).
    #[serde(default)]
    pub accounts: Vec<GenesisAccount>,
}

/// A validator defined in the genesis file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Initial stake in units.
    pub stake: u64,
}

/// A pre-funded account in the genesis file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAccount {
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Initial balance in units.
    pub balance: u32,
}

impl GenesisConfig {
    /// Parse a genesis config from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }
}

impl NodeConfig {
    /// Parse a node config from TOML string.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_node_config() {
        let toml = r#"
validator_index = 0
key_file = "validator.key"
listen = "0.0.0.0:50051"
peers = ["http://10.0.0.2:50051", "http://10.0.0.3:50051"]
"#;
        let cfg = NodeConfig::from_toml(toml).unwrap();
        assert_eq!(cfg.validator_index, 0);
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.log_capacity, 1_000_000); // default
        assert_eq!(cfg.event_interval_ms, 100); // default
    }

    #[test]
    fn parse_genesis() {
        let toml = r#"
network = "zero-devnet"

[[validators]]
public_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
stake = 100

[[validators]]
public_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
stake = 100

[[accounts]]
public_key = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
balance = 1000000
"#;
        let genesis = GenesisConfig::from_toml(toml).unwrap();
        assert_eq!(genesis.network, "zero-devnet");
        assert_eq!(genesis.validators.len(), 2);
        assert_eq!(genesis.accounts.len(), 1);
        assert_eq!(genesis.accounts[0].balance, 1_000_000);
    }

    #[test]
    fn genesis_roundtrip() {
        let genesis = GenesisConfig {
            network: "test".into(),
            validators: vec![GenesisValidator {
                public_key: "aa".repeat(32),
                stake: 100,
            }],
            accounts: vec![],
        };
        let s = genesis.to_toml().unwrap();
        let genesis2 = GenesisConfig::from_toml(&s).unwrap();
        assert_eq!(genesis2.network, "test");
        assert_eq!(genesis2.validators.len(), 1);
    }
}
