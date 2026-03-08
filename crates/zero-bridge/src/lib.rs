//! Zero Bridge Attestation Service
//!
//! Run by each Trinity Validator to bridge assets between Ethereum L2s and Zero.
//!
//! Bridge-In flow (Deposit USDC/USDT → Mint Z):
//!   1. Watch vault `Deposited(depositor, token, amount, zeroRecipient)` events
//!   2. Independently verify the deposit on the source chain
//!   3. Create and sign a `BridgeOp::Mint` attestation (Ed25519)
//!   4. Share signature with other Trinity Validators
//!   5. Once 2-of-3 collected, execute mint on Zero chain
//!
//! Bridge-Out flow (Burn Z → Release USDC/USDT):
//!   1. Watch Zero chain for burn requests
//!   2. Create and sign EIP-712 `Release` message (ECDSA/secp256k1)
//!   3. Share signature with other Trinity Validators
//!   4. Once 2-of-3 collected, submit `release()` to vault contract

pub mod eip712;
pub mod events;
pub mod config;
pub mod coordinator;
pub mod rpc;
pub mod http;
pub mod service;
pub mod watcher;

pub use eip712::{Eip712Signer, ReleaseSigning, DomainSeparator, ReleaseParams};
pub use events::{DepositEvent, ReleaseEvent, parse_deposit_log, parse_release_log};
pub use config::BridgeConfig;
pub use coordinator::{SignatureCollector, PendingOperation};
