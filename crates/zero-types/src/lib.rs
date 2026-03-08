pub mod transfer;
pub mod account;
pub mod block;
pub mod error;
pub mod params;
pub mod config;

pub use transfer::Transfer;
pub use account::Account;
pub use block::{BlockHash, BlockRef};
pub use error::ZeroError;
pub use config::{NodeConfig, GenesisConfig};

/// Public key: 32-byte Ed25519 public key.
pub type PubKey = [u8; 32];

/// Signature: 64-byte Ed25519 signature (full, not truncated).
/// Wire format may truncate to 28 bytes; internally we always use full.
pub type Signature = [u8; 64];

/// Hash: 32-byte BLAKE3 hash.
pub type Hash = [u8; 32];

/// Validator index within the current committee.
pub type ValidatorIndex = u16;

/// Consensus round number.
pub type Round = u32;

/// Amount in units. 1 unit = 0.01 Z. 100 units = 1 Z.
pub type Amount = u32;

/// Per-account monotonic nonce.
pub type Nonce = u32;

/// Epoch number for fee distribution.
pub type Epoch = u64;

/// Timestamp in milliseconds since Unix epoch.
pub type TimestampMs = u64;
