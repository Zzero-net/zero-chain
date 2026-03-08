use std::collections::HashMap;

use zero_types::{
    PubKey, TimestampMs,
    params::{MIN_VALIDATOR_STAKE, UNBONDING_PERIOD_SECS},
};

/// An entry in the unbonding queue.
#[derive(Debug, Clone)]
pub struct UnbondingEntry {
    pub validator: PubKey,
    pub amount: u64,
    /// Timestamp (ms) when unbonding was initiated.
    pub initiated_at: TimestampMs,
}

/// Tracks validator stakes and unbonding state.
pub struct StakeStore {
    /// Current staked amount per validator.
    stakes: HashMap<PubKey, u64>,
    /// Pending unbonding entries.
    unbonding: Vec<UnbondingEntry>,
}

impl StakeStore {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            unbonding: Vec::new(),
        }
    }

    /// Add stake for a validator. Returns new total stake.
    pub fn stake(&mut self, validator: &PubKey, amount: u64) -> u64 {
        let entry = self.stakes.entry(*validator).or_insert(0);
        *entry += amount;
        *entry
    }

    /// Begin unstaking. Moves amount from active stake to unbonding queue.
    /// Returns Err if insufficient stake.
    pub fn begin_unstake(
        &mut self,
        validator: &PubKey,
        amount: u64,
        now_ms: TimestampMs,
    ) -> Result<(), StakeError> {
        let current = self.stakes.get(validator).copied().unwrap_or(0);
        if amount > current {
            return Err(StakeError::InsufficientStake {
                have: current,
                want: amount,
            });
        }

        // Deduct from active stake
        let entry = self
            .stakes
            .get_mut(validator)
            .expect("validator stake must exist after balance check");
        *entry -= amount;
        if *entry == 0 {
            self.stakes.remove(validator);
        }

        // Add to unbonding queue
        self.unbonding.push(UnbondingEntry {
            validator: *validator,
            amount,
            initiated_at: now_ms,
        });

        Ok(())
    }

    /// Complete unbonding for entries past the 7-day period.
    /// Returns list of (validator, amount) pairs ready to be credited back.
    pub fn complete_unbonding(&mut self, now_ms: TimestampMs) -> Vec<(PubKey, u64)> {
        let threshold_ms = UNBONDING_PERIOD_SECS * 1000;
        let mut completed = Vec::new();
        let mut remaining = Vec::new();

        for entry in self.unbonding.drain(..) {
            if now_ms.saturating_sub(entry.initiated_at) >= threshold_ms {
                completed.push((entry.validator, entry.amount));
            } else {
                remaining.push(entry);
            }
        }

        self.unbonding = remaining;
        completed
    }

    /// Get current staked amount for a validator.
    pub fn staked(&self, validator: &PubKey) -> u64 {
        self.stakes.get(validator).copied().unwrap_or(0)
    }

    /// Check if a validator meets the minimum stake requirement.
    pub fn is_active_validator(&self, validator: &PubKey) -> bool {
        self.staked(validator) >= MIN_VALIDATOR_STAKE
    }

    /// Get all active validators (stake >= minimum), sorted by stake descending.
    pub fn active_validators(&self) -> Vec<(PubKey, u64)> {
        let mut validators: Vec<_> = self
            .stakes
            .iter()
            .filter(|(_, stake)| **stake >= MIN_VALIDATOR_STAKE)
            .map(|(pk, &stake)| (*pk, stake))
            .collect();
        validators.sort_by(|a, b| b.1.cmp(&a.1));
        validators
    }

    /// Total active stake across all validators.
    pub fn total_stake(&self) -> u64 {
        self.stakes.values().sum()
    }

    /// Number of active validators (meeting minimum stake).
    pub fn active_count(&self) -> usize {
        self.stakes
            .values()
            .filter(|&&s| s >= MIN_VALIDATOR_STAKE)
            .count()
    }

    /// Number of pending unbonding entries.
    pub fn unbonding_count(&self) -> usize {
        self.unbonding.len()
    }

    /// Total amount currently unbonding.
    pub fn total_unbonding(&self) -> u64 {
        self.unbonding.iter().map(|e| e.amount).sum()
    }

    /// Slash a validator's stake by a percentage (basis points, 10000 = 100%).
    /// Slashes both active stake AND unbonding entries.
    /// Returns the total amount slashed.
    pub fn slash(&mut self, validator: &PubKey, slash_bps: u32) -> u64 {
        let mut total_slashed = 0u64;

        // Slash active stake
        if let Some(stake) = self.stakes.get_mut(validator) {
            let slash_amount = (*stake * slash_bps as u64) / 10_000;
            *stake -= slash_amount;
            total_slashed += slash_amount;
            if *stake == 0 {
                self.stakes.remove(validator);
            }
        }

        // Slash unbonding entries for this validator
        for entry in &mut self.unbonding {
            if entry.validator == *validator {
                let slash_amount = (entry.amount * slash_bps as u64) / 10_000;
                entry.amount -= slash_amount;
                total_slashed += slash_amount;
            }
        }

        // Remove zero-amount unbonding entries
        self.unbonding.retain(|e| e.amount > 0);

        total_slashed
    }
}

impl Default for StakeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StakeError {
    #[error("insufficient stake: have {have}, want {want}")]
    InsufficientStake { have: u64, want: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEVEN_DAYS_MS: u64 = UNBONDING_PERIOD_SECS * 1000;

    #[test]
    fn stake_and_check() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        assert_eq!(store.staked(&v), 0);
        assert!(!store.is_active_validator(&v));

        store.stake(&v, MIN_VALIDATOR_STAKE);
        assert_eq!(store.staked(&v), MIN_VALIDATOR_STAKE);
        assert!(store.is_active_validator(&v));
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn incremental_staking() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, 500_000);
        assert!(!store.is_active_validator(&v)); // below MIN_VALIDATOR_STAKE

        store.stake(&v, 500_000);
        assert!(store.is_active_validator(&v)); // now at 1,000,000 = MIN_VALIDATOR_STAKE
    }

    #[test]
    fn unstake_full() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, MIN_VALIDATOR_STAKE);
        store.begin_unstake(&v, MIN_VALIDATOR_STAKE, 1000).unwrap();

        assert_eq!(store.staked(&v), 0);
        assert!(!store.is_active_validator(&v));
        assert_eq!(store.unbonding_count(), 1);

        // Too early to complete
        let completed = store.complete_unbonding(1000 + SEVEN_DAYS_MS - 1);
        assert!(completed.is_empty());
        assert_eq!(store.unbonding_count(), 1);

        // After 7 days
        let completed = store.complete_unbonding(1000 + SEVEN_DAYS_MS);
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], (v, MIN_VALIDATOR_STAKE));
        assert_eq!(store.unbonding_count(), 0);
    }

    #[test]
    fn unstake_partial() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, MIN_VALIDATOR_STAKE * 2);
        store.begin_unstake(&v, MIN_VALIDATOR_STAKE, 1000).unwrap();

        // Still an active validator with remaining stake
        assert_eq!(store.staked(&v), MIN_VALIDATOR_STAKE);
        assert!(store.is_active_validator(&v));
    }

    #[test]
    fn unstake_insufficient() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, 1000);
        let err = store.begin_unstake(&v, 2000, 1000).unwrap_err();
        assert!(matches!(err, StakeError::InsufficientStake { .. }));
    }

    #[test]
    fn active_validators_sorted() {
        let mut store = StakeStore::new();
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];
        let v3 = [3u8; 32];

        store.stake(&v1, MIN_VALIDATOR_STAKE);
        store.stake(&v2, MIN_VALIDATOR_STAKE * 3);
        store.stake(&v3, MIN_VALIDATOR_STAKE * 2);

        let active = store.active_validators();
        assert_eq!(active.len(), 3);
        // Sorted by stake descending
        assert_eq!(active[0].0, v2);
        assert_eq!(active[1].0, v3);
        assert_eq!(active[2].0, v1);
    }

    #[test]
    fn slash_full_stake() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, MIN_VALIDATOR_STAKE);
        let slashed = store.slash(&v, 10_000); // 100%

        assert_eq!(slashed, MIN_VALIDATOR_STAKE);
        assert_eq!(store.staked(&v), 0);
        assert!(!store.is_active_validator(&v));
    }

    #[test]
    fn slash_partial_stake() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, MIN_VALIDATOR_STAKE); // 1,000,000
        let slashed = store.slash(&v, 1_000); // 10%

        assert_eq!(slashed, 100_000);
        assert_eq!(store.staked(&v), 900_000);
        // Below minimum now
        assert!(!store.is_active_validator(&v));
    }

    #[test]
    fn slash_includes_unbonding() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        store.stake(&v, MIN_VALIDATOR_STAKE * 2); // 2,000,000
        store.begin_unstake(&v, MIN_VALIDATOR_STAKE, 1000).unwrap();
        // Active: 1,000,000, Unbonding: 1,000,000

        let slashed = store.slash(&v, 10_000); // 100%

        assert_eq!(slashed, MIN_VALIDATOR_STAKE * 2);
        assert_eq!(store.staked(&v), 0);
        assert_eq!(store.unbonding_count(), 0); // zero-amount entries removed
    }

    #[test]
    fn slash_no_stake() {
        let mut store = StakeStore::new();
        let v = [1u8; 32];

        let slashed = store.slash(&v, 10_000);
        assert_eq!(slashed, 0);
    }

    #[test]
    fn total_stake_and_unbonding() {
        let mut store = StakeStore::new();
        let v1 = [1u8; 32];
        let v2 = [2u8; 32];

        store.stake(&v1, 1000);
        store.stake(&v2, 2000);
        assert_eq!(store.total_stake(), 3000);

        store.begin_unstake(&v1, 500, 0).unwrap();
        assert_eq!(store.total_stake(), 2500);
        assert_eq!(store.total_unbonding(), 500);
    }
}
