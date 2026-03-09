use std::collections::HashMap;

use zero_crypto::{hash::chain_block_hash, verify::verify_transfer};
use zero_types::{
    Hash, PubKey, TimestampMs, Transfer, ZeroError,
    params::{
        ACCOUNT_CREATION_FEE, BRIDGE_CIRCUIT_BREAKER_BPS, DUST_PRUNE_DAYS, DUST_THRESHOLD,
        FEE_SHARE_BRIDGE_OPS_BPS, FEE_SHARE_VALIDATORS_BPS, MAX_BRIDGE_MINT_PER_HOUR,
        MAX_TRANSFER_AMOUNT, MIN_SEND_BALANCE, TRANSFER_FEE,
    },
};

use crate::{AccountStore, RateLimiter, StakeStore, TransferLog};

/// Executes finalized transfers against the account state.
///
/// This is the entire state machine. For each transfer:
///   1. Check rate limit
///   2. Verify signature
///   3. Check sender has minimum send balance
///   4. Check sender has sufficient balance (amount + fee + creation fee if new recipient)
///   5. Check nonce is correct (expected = current + 1)
///   6. Debit sender (balance -= total_cost, nonce += 1)
///   7. Credit receiver (balance += amount)
///   8. Append to transfer log
///   9. Collect fees into fee pool
pub struct TransferExecutor {
    accounts: AccountStore,
    transfer_log: TransferLog,
    rate_limiter: RateLimiter,
    stake_store: StakeStore,
    fee_pool: u64,
    bridge_reserve: u64,
    protocol_reserve: u64,
    /// Accounts below dust threshold. Maps pubkey → timestamp when first detected.
    dust_candidates: HashMap<PubKey, TimestampMs>,
    /// Circuit breaker: total Z minted in the current 24h window.
    bridge_minted_in_window: u64,
    /// Start of the current 24h circuit breaker window (ms since epoch).
    bridge_window_start: TimestampMs,
    /// Total supply snapshot at the start of the current window (for circuit breaker calculation).
    bridge_window_supply: u64,
}

/// Result of executing a single transfer.
#[derive(Debug)]
pub struct ExecResult {
    pub seq: u64,
    pub hash: Hash,
    pub fee: u32,
}

/// Result of distributing accumulated fees at an epoch boundary.
#[derive(Debug, Clone)]
pub struct FeeDistribution {
    /// Total fees distributed this epoch.
    pub total: u64,
    /// Amount allocated to validators (sum of all individual shares).
    pub validator_total: u64,
    /// Amount added to bridge reserve.
    pub bridge_amount: u64,
    /// Amount added to protocol reserve.
    pub protocol_amount: u64,
    /// Individual validator payouts: (pubkey, amount credited).
    pub validator_payouts: Vec<(PubKey, u64)>,
}

impl TransferExecutor {
    /// Create a new executor with the given transfer log capacity.
    pub fn new(log_capacity: usize) -> Self {
        Self {
            accounts: AccountStore::new(),
            transfer_log: TransferLog::new(log_capacity),
            rate_limiter: RateLimiter::new(),
            stake_store: StakeStore::new(),
            fee_pool: 0,
            bridge_reserve: 0,
            protocol_reserve: 0,
            dust_candidates: HashMap::new(),
            bridge_minted_in_window: 0,
            bridge_window_start: 0,
            bridge_window_supply: 0,
        }
    }

    /// Compute the total fee for a transfer (base fee + account creation fee if applicable).
    fn total_fee(&self, tx: &Transfer) -> u32 {
        let mut fee = TRANSFER_FEE;
        let receiver = self.accounts.get_or_default(&tx.to);
        if receiver.balance == 0 && receiver.nonce == 0 {
            fee += ACCOUNT_CREATION_FEE;
        }
        fee
    }

    /// Validate a transfer without executing it.
    pub fn validate(&self, tx: &Transfer) -> Result<(), ZeroError> {
        // No self-transfers
        if tx.from == tx.to {
            return Err(ZeroError::SelfTransfer);
        }

        // Amount bounds
        if tx.amount == 0 {
            return Err(ZeroError::ZeroAmount);
        }
        if tx.amount > MAX_TRANSFER_AMOUNT {
            return Err(ZeroError::AmountExceedsMax(tx.amount, MAX_TRANSFER_AMOUNT));
        }

        // Verify signature
        verify_transfer(tx)?;

        // Check nonce
        let expected_nonce = self.accounts.nonce(&tx.from) + 1;
        if tx.nonce != expected_nonce {
            return Err(ZeroError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        // Check sender state
        let sender = self.accounts.get_or_default(&tx.from);
        if sender.is_frozen() {
            return Err(ZeroError::AccountFrozen);
        }

        // Minimum send balance check
        if sender.balance < MIN_SEND_BALANCE {
            return Err(ZeroError::BelowMinSendBalance(
                sender.balance,
                MIN_SEND_BALANCE,
            ));
        }

        // Check balance (amount + base fee + account creation fee if new recipient)
        let fee = self.total_fee(tx);
        let total_cost = tx.amount + fee;
        if sender.balance < total_cost {
            return Err(ZeroError::InsufficientBalance {
                have: sender.balance,
                need: total_cost,
                amount: tx.amount,
                fee,
            });
        }

        Ok(())
    }

    /// Check rate limit for a transfer. Call this before validate/execute.
    pub fn check_rate_limit(
        &mut self,
        tx: &Transfer,
        now_ms: TimestampMs,
    ) -> Result<(), ZeroError> {
        self.rate_limiter
            .check(&tx.from, now_ms)
            .map_err(ZeroError::RateLimitExceeded)
    }

    /// Execute a single validated transfer. Returns the sequence number and hash.
    ///
    /// IMPORTANT: caller should validate first, or use `execute` which validates internally.
    fn execute_unchecked(&mut self, tx: &Transfer) -> ExecResult {
        let tx_bytes = tx.to_storage_bytes();
        let tx_hash = zero_crypto::blake3_hash(&tx_bytes);

        let fee = self.total_fee(tx);

        // Compute new head hashes for sender and receiver chains
        let sender_account = self.accounts.get_or_default(&tx.from);
        let receiver_account = self.accounts.get_or_default(&tx.to);

        let sender_new_head = chain_block_hash(
            &sender_account.head,
            &tx_hash,
            sender_account.balance - tx.amount - fee,
        );
        let receiver_new_head = chain_block_hash(
            &receiver_account.head,
            &tx_hash,
            receiver_account.balance + tx.amount,
        );

        // Apply state changes
        self.accounts
            .debit(&tx.from, tx.amount, fee, sender_new_head);
        self.accounts.credit(&tx.to, tx.amount, receiver_new_head);

        // Append to log
        let seq = self.transfer_log.append(tx, tx_hash);

        // Collect fee
        self.fee_pool += fee as u64;

        ExecResult {
            seq,
            hash: tx_hash,
            fee,
        }
    }

    /// Validate and execute a single transfer (no rate limit check — use execute_with_time for that).
    pub fn execute(&mut self, tx: &Transfer) -> Result<ExecResult, ZeroError> {
        self.validate(tx)?;
        Ok(self.execute_unchecked(tx))
    }

    /// Check rate limit, validate, and execute a single transfer.
    pub fn execute_with_time(
        &mut self,
        tx: &Transfer,
        now_ms: TimestampMs,
    ) -> Result<ExecResult, ZeroError> {
        self.check_rate_limit(tx, now_ms)?;
        self.validate(tx)?;
        let result = self.execute_unchecked(tx);
        self.update_dust_tracking(&tx.from, now_ms);
        // Receiver got credited — remove from dust candidates if present
        self.dust_candidates.remove(&tx.to);
        Ok(result)
    }

    /// Execute a batch of transfers. Returns results for successful ones
    /// and errors for failed ones.
    pub fn execute_batch(&mut self, transfers: &[Transfer]) -> Vec<Result<ExecResult, ZeroError>> {
        transfers.iter().map(|tx| self.execute(tx)).collect()
    }

    /// Execute a batch with rate limiting.
    pub fn execute_batch_with_time(
        &mut self,
        transfers: &[Transfer],
        now_ms: TimestampMs,
    ) -> Vec<Result<ExecResult, ZeroError>> {
        transfers
            .iter()
            .map(|tx| self.execute_with_time(tx, now_ms))
            .collect()
    }

    /// Reference to the account store.
    pub fn accounts(&self) -> &AccountStore {
        &self.accounts
    }

    /// Reference to the transfer log.
    pub fn transfer_log(&self) -> &TransferLog {
        &self.transfer_log
    }

    /// Current accumulated fee pool (in units).
    pub fn fee_pool(&self) -> u64 {
        self.fee_pool
    }

    /// Add a fee to the fee pool (e.g. bridge-out fee).
    pub fn collect_fee(&mut self, amount: u64) {
        self.fee_pool += amount;
    }

    /// Track whether an account has fallen below the dust threshold.
    fn update_dust_tracking(&mut self, key: &PubKey, now_ms: TimestampMs) {
        let balance = self.accounts.balance(key);
        if balance > 0 && balance < DUST_THRESHOLD {
            self.dust_candidates.entry(*key).or_insert(now_ms);
        } else {
            self.dust_candidates.remove(key);
        }
    }

    /// Prune accounts that have been below the dust threshold for DUST_PRUNE_DAYS.
    /// Returns the number of accounts pruned and total units reclaimed.
    pub fn prune_dust(&mut self, now_ms: TimestampMs) -> (usize, u64) {
        let threshold_ms = DUST_PRUNE_DAYS as u64 * 24 * 60 * 60 * 1000;
        let mut to_prune = Vec::new();

        for (key, detected_at) in &self.dust_candidates {
            if now_ms.saturating_sub(*detected_at) >= threshold_ms {
                let balance = self.accounts.balance(key);
                if balance > 0 && balance < DUST_THRESHOLD {
                    to_prune.push((*key, balance));
                }
            }
        }

        let mut pruned = 0usize;
        let mut reclaimed = 0u64;
        for (key, balance) in &to_prune {
            self.accounts.burn(key, *balance);
            self.dust_candidates.remove(key);
            pruned += 1;
            reclaimed += *balance as u64;
        }

        (pruned, reclaimed)
    }

    /// Number of accounts currently tracked as dust candidates.
    pub fn dust_candidate_count(&self) -> usize {
        self.dust_candidates.len()
    }

    /// Distribute accumulated fees according to the fee split (50/35/15).
    /// Credits each validator's account proportional to their stake.
    /// Accumulates bridge and protocol reserves.
    pub fn distribute_fees(&mut self, validators: &[(&PubKey, u64)]) -> FeeDistribution {
        let total = self.fee_pool;
        if total == 0 {
            return FeeDistribution {
                total: 0,
                validator_total: 0,
                bridge_amount: 0,
                protocol_amount: 0,
                validator_payouts: Vec::new(),
            };
        }

        let validator_total = total * FEE_SHARE_VALIDATORS_BPS as u64 / 10_000;
        let bridge_amount = total * FEE_SHARE_BRIDGE_OPS_BPS as u64 / 10_000;
        // Protocol gets the remainder to avoid rounding loss
        let protocol_amount = total - validator_total - bridge_amount;

        // Distribute validator share proportional to stake
        let total_stake: u64 = validators.iter().map(|(_, s)| *s).sum();
        let mut payouts = Vec::with_capacity(validators.len());
        let mut paid = 0u64;

        if total_stake > 0 && !validators.is_empty() {
            for (i, (pk, stake)) in validators.iter().enumerate() {
                let share = if i == validators.len() - 1 {
                    // Last validator gets remainder to avoid rounding loss
                    validator_total - paid
                } else {
                    validator_total * stake / total_stake
                };
                self.accounts.mint(pk, share as u32);
                payouts.push((**pk, share));
                paid += share;
            }
        }

        self.bridge_reserve += bridge_amount;
        self.protocol_reserve += protocol_amount;
        self.fee_pool = 0;

        FeeDistribution {
            total,
            validator_total,
            bridge_amount,
            protocol_amount,
            validator_payouts: payouts,
        }
    }

    /// Drain the fee pool without splitting (legacy/testing). Returns the amount drained.
    pub fn drain_fee_pool(&mut self) -> u64 {
        let fees = self.fee_pool;
        self.fee_pool = 0;
        fees
    }

    /// Clean up rate limiter state (call periodically).
    pub fn cleanup_rate_limiter(&mut self, now_ms: TimestampMs) {
        self.rate_limiter.cleanup(now_ms);
    }

    /// Mint Z tokens directly (for genesis funding and fee distribution).
    pub fn mint(&self, to: &[u8; 32], amount: u32) {
        self.accounts.mint(to, amount);
    }

    /// Mint Z tokens via bridge-in with circuit breaker protection.
    /// Enforces: max 20% of total supply per 24h window, max hourly rate.
    pub fn bridge_mint(
        &mut self,
        to: &[u8; 32],
        amount: u64,
        now_ms: TimestampMs,
    ) -> Result<(), ZeroError> {
        let window_duration_ms: u64 = 24 * 60 * 60 * 1000;

        // Reset window if expired or not yet initialized
        if self.bridge_window_start == 0 || now_ms >= self.bridge_window_start + window_duration_ms
        {
            self.bridge_minted_in_window = 0;
            self.bridge_window_start = now_ms;
            self.bridge_window_supply = self.accounts.total_supply();
        }

        // Circuit breaker: max BRIDGE_CIRCUIT_BREAKER_BPS of supply (at window start) per 24h
        let total_supply = self.bridge_window_supply;
        // If supply is zero (bootstrapping), allow up to MAX_BRIDGE_MINT_PER_HOUR
        let max_window = if total_supply > 0 {
            total_supply * BRIDGE_CIRCUIT_BREAKER_BPS as u64 / 10_000
        } else {
            MAX_BRIDGE_MINT_PER_HOUR
        };

        if self.bridge_minted_in_window + amount > max_window {
            return Err(ZeroError::BridgeCircuitBreaker {
                requested: amount,
                remaining: max_window.saturating_sub(self.bridge_minted_in_window),
                window_max: max_window,
            });
        }

        let amount_u32 = u32::try_from(amount)
            .map_err(|_| ZeroError::AmountExceedsMax(u32::MAX, MAX_TRANSFER_AMOUNT))?;
        self.accounts.mint(to, amount_u32);
        self.bridge_minted_in_window += amount;
        Ok(())
    }

    /// Current amount minted in the active 24h window.
    pub fn bridge_minted_in_window(&self) -> u64 {
        self.bridge_minted_in_window
    }

    /// Current accumulated bridge reserve (in units).
    pub fn bridge_reserve(&self) -> u64 {
        self.bridge_reserve
    }

    /// Current accumulated protocol reserve (in units).
    pub fn protocol_reserve(&self) -> u64 {
        self.protocol_reserve
    }

    /// Restore reserves from a snapshot. Called during startup.
    pub fn restore_reserves(&mut self, fee_pool: u64, bridge_reserve: u64, protocol_reserve: u64) {
        self.fee_pool = fee_pool;
        self.bridge_reserve = bridge_reserve;
        self.protocol_reserve = protocol_reserve;
    }

    /// Withdraw from bridge reserve (for paying vault gas). Returns amount withdrawn.
    pub fn withdraw_bridge_reserve(&mut self, amount: u64) -> u64 {
        let withdrawn = amount.min(self.bridge_reserve);
        self.bridge_reserve -= withdrawn;
        withdrawn
    }

    /// Stake Z tokens. Deducts from account balance and adds to stake store.
    pub fn stake(&mut self, validator: &PubKey, amount: u64) -> Result<u64, ZeroError> {
        let amount_u32 = u32::try_from(amount)
            .map_err(|_| ZeroError::AmountExceedsMax(u32::MAX, MAX_TRANSFER_AMOUNT))?;
        let balance = self.accounts.balance(validator);
        if (balance as u64) < amount {
            return Err(ZeroError::InsufficientBalance {
                have: balance,
                need: amount_u32,
                amount: amount_u32,
                fee: 0,
            });
        }
        self.accounts.burn(validator, amount_u32);
        let new_stake = self.stake_store.stake(validator, amount);
        Ok(new_stake)
    }

    /// Begin unstaking. Moves stake to unbonding queue (7-day wait).
    pub fn begin_unstake(
        &mut self,
        validator: &PubKey,
        amount: u64,
        now_ms: TimestampMs,
    ) -> Result<(), ZeroError> {
        self.stake_store
            .begin_unstake(validator, amount, now_ms)
            .map_err(|e| ZeroError::Storage(e.to_string()))
    }

    /// Complete unbonding for entries past the 7-day period.
    /// Credits returned stake to validator accounts.
    pub fn complete_unbonding(&mut self, now_ms: TimestampMs) -> Vec<(PubKey, u64)> {
        let completed = self.stake_store.complete_unbonding(now_ms);
        for (pk, amount) in &completed {
            self.accounts.mint(pk, *amount as u32);
        }
        completed
    }

    /// Reference to the stake store.
    pub fn stake_store(&self) -> &StakeStore {
        &self.stake_store
    }

    /// Mutable reference to the stake store (for seeding genesis stakes).
    pub fn stake_store_mut(&mut self) -> &mut StakeStore {
        &mut self.stake_store
    }

    /// Slash a validator's stake (both active and unbonding) by slash_bps.
    /// Slashed funds are added to the protocol reserve (burned from circulation).
    /// Returns the total amount slashed.
    pub fn slash_validator(&mut self, validator: &PubKey, slash_bps: u32) -> u64 {
        let slashed = self.stake_store.slash(validator, slash_bps);
        self.protocol_reserve += slashed;
        slashed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_crypto::keypair::KeyPair;

    fn funded_executor() -> (TransferExecutor, KeyPair, KeyPair) {
        let exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        // Fund sender with 100,000 units = 1,000 Z = $10
        exec.mint(&sender.public_key(), 100_000);

        (exec, sender, receiver)
    }

    fn make_signed_transfer(
        sender: &KeyPair,
        receiver_pk: &[u8; 32],
        amount: u32,
        nonce: u32,
    ) -> Transfer {
        let mut tx = Transfer {
            from: sender.public_key(),
            to: *receiver_pk,
            amount,
            nonce,
            signature: [0u8; 64],
        };
        tx.signature = sender.sign_transfer(&tx);
        tx
    }

    #[test]
    fn successful_transfer() {
        let (mut exec, sender, receiver) = funded_executor();

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        let result = exec.execute(&tx).unwrap();

        assert_eq!(result.seq, 0);
        // First transfer to new account: fee = TRANSFER_FEE + ACCOUNT_CREATION_FEE
        let expected_fee = TRANSFER_FEE + ACCOUNT_CREATION_FEE;
        assert_eq!(result.fee, expected_fee);
        assert_eq!(
            exec.accounts().balance(&sender.public_key()),
            100_000 - 100 - expected_fee
        );
        assert_eq!(exec.accounts().balance(&receiver.public_key()), 100);
        assert_eq!(exec.fee_pool(), expected_fee as u64);
    }

    #[test]
    fn second_transfer_no_creation_fee() {
        let (mut exec, sender, receiver) = funded_executor();

        // First transfer (triggers account creation fee)
        let tx1 = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        let r1 = exec.execute(&tx1).unwrap();
        assert_eq!(r1.fee, TRANSFER_FEE + ACCOUNT_CREATION_FEE);

        // Second transfer (no creation fee — account already exists)
        let tx2 = make_signed_transfer(&sender, &receiver.public_key(), 100, 2);
        let r2 = exec.execute(&tx2).unwrap();
        assert_eq!(r2.fee, TRANSFER_FEE);
    }

    #[test]
    fn insufficient_balance() {
        let exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        // Fund sender with MIN_SEND_BALANCE (enough to pass min check but not enough for tx)
        exec.mint(&sender.public_key(), MIN_SEND_BALANCE);

        // Try to send more than balance allows (amount + fee + creation fee > balance)
        let tx = make_signed_transfer(&sender, &receiver.public_key(), 50, 1);
        let err = exec.validate(&tx).unwrap_err();
        assert!(matches!(err, ZeroError::InsufficientBalance { .. }));
    }

    #[test]
    fn below_min_send_balance() {
        let exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        // Fund sender below MIN_SEND_BALANCE
        exec.mint(&sender.public_key(), MIN_SEND_BALANCE - 1);

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 10, 1);
        // validate() is &self, not &mut self — but execute() is &mut self
        // We need to call validate directly to avoid the mut requirement
        let err = exec.validate(&tx).unwrap_err();
        assert!(matches!(err, ZeroError::BelowMinSendBalance(_, _)));
    }

    #[test]
    fn wrong_nonce() {
        let (mut exec, sender, receiver) = funded_executor();

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 5); // expected 1
        let err = exec.execute(&tx).unwrap_err();
        assert!(matches!(err, ZeroError::InvalidNonce { .. }));
    }

    #[test]
    fn self_transfer_rejected() {
        let (mut exec, sender, _) = funded_executor();

        let tx = make_signed_transfer(&sender, &sender.public_key(), 100, 1);
        let err = exec.execute(&tx).unwrap_err();
        assert!(matches!(err, ZeroError::SelfTransfer));
    }

    #[test]
    fn amount_exceeds_max() {
        let (mut exec, sender, receiver) = funded_executor();

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 5000, 1);
        let err = exec.execute(&tx).unwrap_err();
        assert!(matches!(err, ZeroError::AmountExceedsMax(_, _)));
    }

    #[test]
    fn sequential_transfers() {
        let (mut exec, sender, receiver) = funded_executor();

        for i in 1..=5u32 {
            let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, i);
            exec.execute(&tx).unwrap();
        }

        // First transfer has creation fee, rest don't
        let total_fees = (TRANSFER_FEE + ACCOUNT_CREATION_FEE) + TRANSFER_FEE * 4;
        assert_eq!(
            exec.accounts().balance(&sender.public_key()),
            100_000 - 500 - total_fees
        );
        assert_eq!(exec.accounts().balance(&receiver.public_key()), 500);
        assert_eq!(exec.fee_pool(), total_fees as u64);
        assert_eq!(exec.transfer_log().total_written(), 5);
    }

    #[test]
    fn batch_execution() {
        let (mut exec, sender, receiver) = funded_executor();

        let txs: Vec<Transfer> = (1..=3u32)
            .map(|i| make_signed_transfer(&sender, &receiver.public_key(), 50, i))
            .collect();

        let results = exec.execute_batch(&txs);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.is_ok());
        }
    }

    #[test]
    fn fee_pool_drain() {
        let (mut exec, sender, receiver) = funded_executor();

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        exec.execute(&tx).unwrap();

        let expected_fee = (TRANSFER_FEE + ACCOUNT_CREATION_FEE) as u64;
        assert_eq!(exec.fee_pool(), expected_fee);
        let drained = exec.drain_fee_pool();
        assert_eq!(drained, expected_fee);
        assert_eq!(exec.fee_pool(), 0);
    }

    #[test]
    fn rate_limit_with_time() {
        let (mut exec, sender, receiver) = funded_executor();

        // Send MAX_TX_PER_ACCOUNT_PER_SEC transfers in same millisecond window
        for i in 1..=zero_types::params::MAX_TX_PER_ACCOUNT_PER_SEC {
            let tx = make_signed_transfer(&sender, &receiver.public_key(), 1, i);
            exec.execute_with_time(&tx, 1000).unwrap();
        }

        // Next one should be rate limited
        let tx = make_signed_transfer(
            &sender,
            &receiver.public_key(),
            1,
            zero_types::params::MAX_TX_PER_ACCOUNT_PER_SEC + 1,
        );
        let err = exec.execute_with_time(&tx, 1000).unwrap_err();
        assert!(matches!(err, ZeroError::RateLimitExceeded(_)));

        // After window resets, should work again
        let tx2 = make_signed_transfer(
            &sender,
            &receiver.public_key(),
            1,
            zero_types::params::MAX_TX_PER_ACCOUNT_PER_SEC + 1,
        );
        assert!(exec.execute_with_time(&tx2, 2001).is_ok());
    }

    #[test]
    fn fee_distribution_split() {
        let (mut exec, sender, receiver) = funded_executor();

        // Execute a transfer to generate fees
        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        exec.execute(&tx).unwrap();

        let total_fee = (TRANSFER_FEE + ACCOUNT_CREATION_FEE) as u64; // 101
        assert_eq!(exec.fee_pool(), total_fee);

        // Set up 2 validators with equal stake
        let v1 = [0xAAu8; 32];
        let v2 = [0xBBu8; 32];
        let validators = vec![(&v1, 100u64), (&v2, 100u64)];

        let dist = exec.distribute_fees(&validators);

        // 70% validators, 15% bridge, 15% protocol (remainder)
        let expected_validator = total_fee * FEE_SHARE_VALIDATORS_BPS as u64 / 10_000;
        let expected_bridge = total_fee * FEE_SHARE_BRIDGE_OPS_BPS as u64 / 10_000;
        let expected_protocol = total_fee - expected_validator - expected_bridge;

        assert_eq!(dist.total, total_fee);
        assert_eq!(dist.validator_total, expected_validator);
        assert_eq!(dist.bridge_amount, expected_bridge);
        assert_eq!(dist.protocol_amount, expected_protocol);

        // Each validator gets half of the validator pool
        assert_eq!(dist.validator_payouts.len(), 2);

        // Fee pool is drained
        assert_eq!(exec.fee_pool(), 0);

        // Reserves accumulated
        assert_eq!(exec.bridge_reserve(), expected_bridge);
        assert_eq!(exec.protocol_reserve(), expected_protocol);

        // Validator accounts credited
        let v1_balance = exec.accounts().balance(&v1);
        let v2_balance = exec.accounts().balance(&v2);
        assert_eq!(v1_balance as u64 + v2_balance as u64, expected_validator);
    }

    #[test]
    fn fee_distribution_unequal_stake() {
        let mut exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        exec.mint(&sender.public_key(), 100_000);

        // Generate some fees
        for i in 1..=5u32 {
            let tx = make_signed_transfer(&sender, &receiver.public_key(), 10, i);
            exec.execute(&tx).unwrap();
        }

        let total_fee = exec.fee_pool();
        assert!(total_fee > 0);

        // Validator A has 3x the stake of B
        let va = [0x01u8; 32];
        let vb = [0x02u8; 32];
        let validators = vec![(&va, 300u64), (&vb, 100u64)];

        let dist = exec.distribute_fees(&validators);

        // A should get 3x what B gets (approximately, with rounding)
        let a_payout = dist.validator_payouts[0].1;
        let b_payout = dist.validator_payouts[1].1;
        assert!(a_payout > b_payout);
        assert_eq!(a_payout + b_payout, dist.validator_total);

        // Verify accounts credited
        assert_eq!(exec.accounts().balance(&va), a_payout as u32);
        assert_eq!(exec.accounts().balance(&vb), b_payout as u32);
    }

    #[test]
    fn fee_distribution_empty_pool() {
        let mut exec = TransferExecutor::new(1000);

        let v1 = [0xAAu8; 32];
        let validators = vec![(&v1, 100u64)];

        let dist = exec.distribute_fees(&validators);
        assert_eq!(dist.total, 0);
        assert!(dist.validator_payouts.is_empty());
        assert_eq!(exec.bridge_reserve(), 0);
        assert_eq!(exec.protocol_reserve(), 0);
    }

    #[test]
    fn fee_distribution_accumulates_reserves() {
        let (mut exec, sender, receiver) = funded_executor();

        // Execute two transfers across two distribution epochs
        let tx1 = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        exec.execute(&tx1).unwrap();

        let v1 = [0xAAu8; 32];
        let validators = vec![(&v1, 100u64)];
        let dist1 = exec.distribute_fees(&validators);

        let tx2 = make_signed_transfer(&sender, &receiver.public_key(), 100, 2);
        exec.execute(&tx2).unwrap();
        let dist2 = exec.distribute_fees(&validators);

        // Reserves should accumulate across distributions
        assert_eq!(
            exec.bridge_reserve(),
            dist1.bridge_amount + dist2.bridge_amount
        );
        assert_eq!(
            exec.protocol_reserve(),
            dist1.protocol_amount + dist2.protocol_amount
        );
    }

    #[test]
    fn withdraw_bridge_reserve() {
        let (mut exec, sender, receiver) = funded_executor();

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        exec.execute(&tx).unwrap();

        let v1 = [0xAAu8; 32];
        let validators = vec![(&v1, 100u64)];
        let dist = exec.distribute_fees(&validators);

        let reserve = exec.bridge_reserve();
        assert_eq!(reserve, dist.bridge_amount);

        // Withdraw some
        let withdrawn = exec.withdraw_bridge_reserve(10);
        assert_eq!(withdrawn, 10);
        assert_eq!(exec.bridge_reserve(), reserve - 10);

        // Withdraw more than available
        let withdrawn = exec.withdraw_bridge_reserve(999_999);
        assert_eq!(withdrawn, reserve - 10);
        assert_eq!(exec.bridge_reserve(), 0);
    }

    #[test]
    fn dust_tracking_after_transfer() {
        let mut exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        // Fund sender with exactly 10,400 units so the drain-to-dust math works:
        // tx1: -2,400 - 501 (transfer fee + account creation) = 7,499
        // tx2-tx4: each -2,400 - 1 = -2,401 × 3 = 296
        // tx5: -190 - 1 = 105
        // tx6: -100 - 1 = 4 (dust!)
        exec.mint(&sender.public_key(), 10_400);

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 2400, 1);
        let _ = exec.execute_with_time(&tx, 1000).unwrap();

        // balance = 10,400 - 2,400 - 501 = 7,499. Not dust.
        assert_eq!(exec.dust_candidate_count(), 0);

        // Drain sender close to dust via multiple transfers (max 2,500 each).
        let tx2 = make_signed_transfer(&sender, &receiver.public_key(), 2400, 2);
        let _ = exec.execute_with_time(&tx2, 1001).unwrap();
        // balance = 7,499 - 2,400 - 1 = 5,098
        let tx3 = make_signed_transfer(&sender, &receiver.public_key(), 2400, 3);
        let _ = exec.execute_with_time(&tx3, 1002).unwrap();
        // balance = 5,098 - 2,400 - 1 = 2,697
        let tx4 = make_signed_transfer(&sender, &receiver.public_key(), 2400, 4);
        let _ = exec.execute_with_time(&tx4, 1003).unwrap();
        // balance = 2,697 - 2,400 - 1 = 296
        let tx5 = make_signed_transfer(&sender, &receiver.public_key(), 190, 5);
        let _ = exec.execute_with_time(&tx5, 1004).unwrap();
        // balance = 296 - 190 - 1 = 105
        let tx6 = make_signed_transfer(&sender, &receiver.public_key(), 100, 6);
        let _ = exec.execute_with_time(&tx6, 1005).unwrap();
        // balance = 105 - 100 - 1 = 4. Dust!

        assert_eq!(exec.accounts().balance(&sender.public_key()), 4);
        assert_eq!(exec.dust_candidate_count(), 1);

        // Pruning too early should do nothing (need 30 days)
        let (pruned, _) = exec.prune_dust(1005);
        assert_eq!(pruned, 0);

        // After 30 days, should prune
        let thirty_days_ms = DUST_PRUNE_DAYS as u64 * 24 * 60 * 60 * 1000;
        let (pruned, reclaimed) = exec.prune_dust(1005 + thirty_days_ms);
        assert_eq!(pruned, 1);
        assert_eq!(reclaimed, 4);
        assert_eq!(exec.accounts().balance(&sender.public_key()), 0);
        assert_eq!(exec.dust_candidate_count(), 0);
    }

    #[test]
    fn dust_removed_when_funded() {
        let mut exec = TransferExecutor::new(1000);
        let sender = KeyPair::generate();
        // Fund sender with dust amount
        exec.mint(&sender.public_key(), 5);
        // Manually track as dust
        exec.dust_candidates.insert(sender.public_key(), 0);
        assert_eq!(exec.dust_candidate_count(), 1);

        // Fund them above dust threshold via mint
        exec.mint(&sender.public_key(), 1000);

        // Sending them tokens via execute_with_time should clear dust status
        let funder = KeyPair::generate();
        exec.mint(&funder.public_key(), 100_000);
        let tx = make_signed_transfer(&funder, &sender.public_key(), 100, 1);
        exec.execute_with_time(&tx, 1000).unwrap();

        // Receiver (sender) got credited — should be removed from dust candidates
        assert_eq!(exec.dust_candidate_count(), 0);
    }

    #[test]
    fn stake_and_unstake() {
        let mut exec = TransferExecutor::new(1000);
        let v = KeyPair::generate();
        let pk = v.public_key();

        // Fund validator account
        exec.mint(&pk, 2_000_000); // 20,000 Z

        // Stake minimum (10,000 Z = 1,000,000 units)
        let new_stake = exec.stake(&pk, 1_000_000).unwrap();
        assert_eq!(new_stake, 1_000_000);
        assert_eq!(exec.accounts().balance(&pk), 1_000_000); // 10,000 Z remaining
        assert!(exec.stake_store().is_active_validator(&pk));

        // Begin unstake
        exec.begin_unstake(&pk, 1_000_000, 1000).unwrap();
        assert!(!exec.stake_store().is_active_validator(&pk));
        assert_eq!(exec.stake_store().unbonding_count(), 1);

        // Too early to complete
        let completed = exec.complete_unbonding(1000);
        assert!(completed.is_empty());

        // After 7 days, funds return to account
        let seven_days = 7 * 24 * 60 * 60 * 1000;
        let completed = exec.complete_unbonding(1000 + seven_days);
        assert_eq!(completed.len(), 1);
        assert_eq!(exec.accounts().balance(&pk), 2_000_000); // full balance restored
    }

    #[test]
    fn bridge_mint_basic() {
        let mut exec = TransferExecutor::new(1000);
        let recipient = [0xAAu8; 32];

        exec.bridge_mint(&recipient, 1000, 1000).unwrap();
        assert_eq!(exec.accounts().balance(&recipient), 1000);
        assert_eq!(exec.bridge_minted_in_window(), 1000);
    }

    #[test]
    fn bridge_circuit_breaker_blocks_excess() {
        let mut exec = TransferExecutor::new(1000);
        let funder = [0x01u8; 32];
        let recipient = [0x02u8; 32];

        // Seed supply: 100,000 units = 1,000 Z
        exec.mint(&funder, 100_000);

        // Max per 24h = 100,000 * 2000/10000 = 20,000 units
        // Mint up to the limit
        exec.bridge_mint(&recipient, 20_000, 1000).unwrap();

        // Next mint should be blocked
        let err = exec.bridge_mint(&recipient, 1, 1000).unwrap_err();
        assert!(matches!(err, ZeroError::BridgeCircuitBreaker { .. }));
    }

    #[test]
    fn bridge_circuit_breaker_resets_after_window() {
        let mut exec = TransferExecutor::new(1000);
        let funder = [0x01u8; 32];
        let recipient = [0x02u8; 32];

        exec.mint(&funder, 100_000);

        // Fill the window
        exec.bridge_mint(&recipient, 20_000, 1000).unwrap();

        // After 24h, window resets
        let next_day = 1000 + 24 * 60 * 60 * 1000;
        exec.bridge_mint(&recipient, 1000, next_day).unwrap();
        assert_eq!(exec.bridge_minted_in_window(), 1000); // reset + new mint
    }

    #[test]
    fn bridge_mint_bootstrap_allows_initial() {
        let mut exec = TransferExecutor::new(1000);
        let recipient = [0xAAu8; 32];

        // No supply yet — should allow up to MAX_BRIDGE_MINT_PER_HOUR
        exec.bridge_mint(&recipient, 50_000_000, 1000).unwrap();
        assert_eq!(exec.accounts().balance(&recipient), 50_000_000);
    }

    #[test]
    fn slash_validator_adds_to_protocol_reserve() {
        let mut exec = TransferExecutor::new(1000);
        let v = KeyPair::generate();
        let pk = v.public_key();

        exec.mint(&pk, 2_000_000);
        exec.stake(&pk, 1_000_000).unwrap();

        let slashed = exec.slash_validator(&pk, 10_000); // 100% slash
        assert_eq!(slashed, 1_000_000);
        assert_eq!(exec.stake_store().staked(&pk), 0);
        assert_eq!(exec.protocol_reserve(), 1_000_000); // slashed funds → protocol reserve
    }

    #[test]
    fn stake_insufficient_balance() {
        let mut exec = TransferExecutor::new(1000);
        let v = KeyPair::generate();
        exec.mint(&v.public_key(), 100); // only 1 Z

        let err = exec.stake(&v.public_key(), 1_000_000).unwrap_err();
        assert!(matches!(err, ZeroError::InsufficientBalance { .. }));
    }
}
