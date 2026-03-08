use thiserror::Error;

use crate::Amount;

#[derive(Debug, Error)]
pub enum ZeroError {
    #[error("insufficient balance: have {have}, need {need} (amount {amount} + fee {fee})")]
    InsufficientBalance {
        have: Amount,
        need: Amount,
        amount: Amount,
        fee: Amount,
    },

    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u32, got: u32 },

    #[error("invalid signature")]
    InvalidSignature,

    #[error("amount {0} exceeds maximum {1}")]
    AmountExceedsMax(Amount, Amount),

    #[error("zero amount transfer")]
    ZeroAmount,

    #[error("self-transfer not allowed")]
    SelfTransfer,

    #[error("account is frozen")]
    AccountFrozen,

    #[error("sender balance {0} below minimum send threshold {1}")]
    BelowMinSendBalance(Amount, Amount),

    #[error("rate limit exceeded: {0} tx/s for account")]
    RateLimitExceeded(u32),

    #[error("unknown account: {0}")]
    UnknownAccount(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error(
        "bridge circuit breaker: requested {requested}, remaining {remaining} of {window_max} in 24h window"
    )]
    BridgeCircuitBreaker {
        requested: u64,
        remaining: u64,
        window_max: u64,
    },
}
