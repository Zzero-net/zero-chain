//! Bridge service configuration.

use serde::{Deserialize, Serialize};

/// Configuration for a single vault deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Chain name (e.g., "base", "arbitrum")
    pub chain: String,
    /// Chain ID (e.g., 84532 for Base Sepolia, 421614 for Arbitrum Sepolia)
    pub chain_id: u64,
    /// RPC endpoint URL for the source chain
    pub rpc_url: String,
    /// ZeroVault contract address (hex, no 0x prefix)
    pub vault_address: String,
    /// Supported token address (hex, no 0x prefix)
    pub token_address: String,
    /// Token decimals (6 for USDC/USDT)
    pub token_decimals: u8,
    /// Number of block confirmations required before processing a deposit
    pub confirmations: u64,
}

/// Configuration for this Trinity Validator instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrinityConfig {
    /// This validator's Ed25519 private key file (for Zero chain attestations)
    pub ed25519_key_file: String,
    /// This validator's ECDSA private key file (for Ethereum vault signatures)
    pub ecdsa_key_file: String,
    /// Index in the guardian array (0, 1, or 2)
    pub index: usize,
}

/// Peer Trinity Validator endpoint for signature coordination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer's HTTP endpoint for signature exchange
    pub endpoint: String,
    /// Peer's Ed25519 public key (hex) for identity verification
    pub ed25519_pubkey: String,
    /// Peer's Ethereum address (hex) for guardian verification
    pub eth_address: String,
}

/// Full bridge service configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Vault deployments to watch
    pub vaults: Vec<VaultConfig>,
    /// This Trinity Validator's keys
    pub trinity: TrinityConfig,
    /// Other Trinity Validator endpoints
    pub peers: Vec<PeerConfig>,
    /// Zero chain gRPC endpoint
    pub zero_rpc: String,
    /// HTTP listen address for coordination API (e.g., "0.0.0.0:9100")
    pub listen_addr: String,
    /// Poll interval for new events (milliseconds)
    pub poll_interval_ms: u64,
}

impl BridgeConfig {
    /// Parse vault address from hex string to 20-byte array.
    pub fn vault_address_bytes(hex_str: &str) -> Result<[u8; 20], hex::FromHexError> {
        let clean = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(clean)?;
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(addr)
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            vaults: vec![VaultConfig {
                chain: "base-sepolia".into(),
                chain_id: 84532,
                rpc_url: "https://sepolia.base.org".into(),
                vault_address: "0000000000000000000000000000000000000000".into(),
                token_address: "0000000000000000000000000000000000000000".into(),
                token_decimals: 6,
                confirmations: 12,
            }],
            trinity: TrinityConfig {
                ed25519_key_file: "trinity_ed25519.key".into(),
                ecdsa_key_file: "trinity_ecdsa.key".into(),
                index: 0,
            },
            peers: vec![],
            zero_rpc: "http://127.0.0.1:50051".into(),
            listen_addr: "0.0.0.0:9100".into(),
            poll_interval_ms: 5000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes() {
        let config = BridgeConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("base-sepolia"));

        let parsed: BridgeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.vaults[0].chain, "base-sepolia");
        assert_eq!(parsed.vaults[0].chain_id, 84532);
    }

    #[test]
    fn vault_address_parsing() {
        let addr = BridgeConfig::vault_address_bytes("0xaabbccdd11223344556677889900aabbccddeeff")
            .unwrap();
        assert_eq!(addr[0], 0xaa);
        assert_eq!(addr[19], 0xff);

        // Without 0x prefix
        let addr2 =
            BridgeConfig::vault_address_bytes("aabbccdd11223344556677889900aabbccddeeff").unwrap();
        assert_eq!(addr, addr2);
    }
}
