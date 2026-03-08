use crate::Amount;

// === Network Parameters ===

/// Maximum number of active validators.
pub const MAX_VALIDATORS: usize = 1024;

/// Minimum stake to become a validator (10,000 Z).
pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000; // 10,000 Z × 100 units/Z

/// Unbonding period in seconds (7 days).
pub const UNBONDING_PERIOD_SECS: u64 = 7 * 24 * 60 * 60;

/// Epoch length in finalized events for fee distribution.
pub const EPOCH_LENGTH: u64 = 10_000;

// === Unit System ===
// 1 unit = 0.01 Z (2 decimal places)
// 100 units = 1 Z
// Z is pegged 1:1 to $0.01 (1 penny)
// So 1 unit = $0.0001

/// Units per Z token.
pub const UNITS_PER_Z: u32 = 100;

// === Transfer Parameters ===

/// Flat fee per transfer: 1 unit = 0.01 Z.
pub const TRANSFER_FEE: Amount = 1;

/// Maximum transfer amount: 2,500 units = 25 Z.
pub const MAX_TRANSFER_AMOUNT: Amount = 2_500;

/// Account creation fee: 10,000 units = 100 Z = $1.00.
/// Charged to sender on first transfer to a new (zero-balance, zero-nonce) account.
/// High enough to prevent dust account spam at scale.
pub const ACCOUNT_CREATION_FEE: Amount = 10_000;

/// Minimum balance to send: 100 units = 1 Z.
/// Accounts below this can only receive.
pub const MIN_SEND_BALANCE: Amount = 100;

// === Fee Distribution (basis points, total must = 10,000) ===

/// Validator share of fees: 50%.
pub const FEE_SHARE_VALIDATORS_BPS: u32 = 5_000;

/// Bridge reserve share: 35%.
/// Pays for vault contract gas on source/dest chains.
pub const FEE_SHARE_BRIDGE_OPS_BPS: u32 = 3_500;

/// Protocol reserve share: 15%.
/// Emergency fund, future development.
pub const FEE_SHARE_PROTOCOL_BPS: u32 = 1_500;

// Compile-time check: fee shares must sum to 10,000 BPS (100%).
const _: () = assert!(
    FEE_SHARE_VALIDATORS_BPS + FEE_SHARE_BRIDGE_OPS_BPS + FEE_SHARE_PROTOCOL_BPS == 10_000
);

// === Rate Limiting ===

/// Maximum transactions per account per second.
pub const MAX_TX_PER_ACCOUNT_PER_SEC: u32 = 100;

/// Maximum bridge mints per hour (token bucket capacity).
pub const MAX_BRIDGE_MINT_PER_HOUR: u64 = 100_000_000; // 1M Z in units

// === Validator Scoring ===

/// Initial trust score for new validators (out of 1000).
pub const INITIAL_TRUST_SCORE: u32 = 500;

/// Maximum trust score.
pub const MAX_TRUST_SCORE: u32 = 1000;

/// Minimum trust score before ejection.
pub const MIN_TRUST_SCORE: u32 = 100;

/// Percentage of bottom validators ejected per epoch (in basis points, 500 = 5%).
pub const EJECTION_RATE_BPS: u32 = 500;

/// Trust score reward for producing a valid, timely event.
pub const SCORE_REWARD_EVENT: u32 = 1;

/// Trust score penalty for missing a round (no event produced when expected).
pub const SCORE_PENALTY_MISS: u32 = 5;

/// Trust score penalty for late event (received after threshold).
pub const SCORE_PENALTY_LATE: u32 = 2;

/// Trust score penalty for equivocation (two events same round). Instant ejection.
pub const SCORE_PENALTY_EQUIVOCATION: u32 = 1000;

/// Threshold in milliseconds for considering an event "late".
/// Events received more than this many ms after their timestamp are penalized.
pub const LATE_EVENT_THRESHOLD_MS: u64 = 5_000;

// === Slashing Parameters (basis points, 10000 = 100%) ===

/// Equivocation (two conflicting events in same round): slash 100% of stake.
pub const SLASH_EQUIVOCATION_BPS: u32 = 10_000;

/// Prolonged downtime (trust score falls below minimum): slash 10% of stake.
pub const SLASH_DOWNTIME_BPS: u32 = 1_000;

/// Invalid bridge attestation (guardian-only offense): slash 100% of stake.
pub const SLASH_INVALID_ATTESTATION_BPS: u32 = 10_000;

// === Bridge Parameters ===

/// Number of source chain confirmations before attesting a deposit.
/// Launch paths: USDC on Base, USDT on Arbitrum.
/// Ethereum L1 and Solana reserved for future expansion.
pub const BRIDGE_CONFIRMATIONS_BASE: u32 = 20;
pub const BRIDGE_CONFIRMATIONS_ARBITRUM: u32 = 20;

/// Circuit breaker: max mint as percentage of reserves per 24h (basis points, 2000 = 20%).
pub const BRIDGE_CIRCUIT_BREAKER_BPS: u32 = 2000;

// === Dust / Pruning ===

/// Dust threshold: 10 units = 0.10 Z.
/// Accounts below this for DUST_PRUNE_DAYS can be pruned.
pub const DUST_THRESHOLD: Amount = 10;

/// Days an account must be below dust threshold before pruning.
pub const DUST_PRUNE_DAYS: u32 = 30;
