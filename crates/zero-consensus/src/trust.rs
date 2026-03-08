use std::collections::HashMap;

use zero_types::{
    ValidatorIndex,
    params::{
        EJECTION_RATE_BPS, INITIAL_TRUST_SCORE, MAX_TRUST_SCORE, MAX_VALIDATORS, MIN_TRUST_SCORE,
        SCORE_PENALTY_EQUIVOCATION, SCORE_PENALTY_LATE, SCORE_PENALTY_MISS, SCORE_REWARD_EVENT,
    },
};

/// Tracks trust scores for all validators.
///
/// Trust scores determine validator reputation and eligibility.
/// Validators below MIN_TRUST_SCORE are ejected.
/// Bottom EJECTION_RATE_BPS% are ejected each epoch.
pub struct TrustScorer {
    scores: HashMap<ValidatorIndex, u32>,
}

impl TrustScorer {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
        }
    }

    /// Register a new validator with initial trust score.
    pub fn register(&mut self, index: ValidatorIndex) {
        self.scores.insert(index, INITIAL_TRUST_SCORE);
    }

    /// Get a validator's current trust score.
    pub fn score(&self, index: ValidatorIndex) -> u32 {
        self.scores.get(&index).copied().unwrap_or(0)
    }

    /// Reward a validator for producing a valid, timely event.
    pub fn reward_event(&mut self, index: ValidatorIndex) {
        if let Some(score) = self.scores.get_mut(&index) {
            *score = (*score + SCORE_REWARD_EVENT).min(MAX_TRUST_SCORE);
        }
    }

    /// Penalize a validator for missing a round.
    pub fn penalize_miss(&mut self, index: ValidatorIndex) {
        if let Some(score) = self.scores.get_mut(&index) {
            *score = score.saturating_sub(SCORE_PENALTY_MISS);
        }
    }

    /// Penalize a validator for a late event.
    pub fn penalize_late(&mut self, index: ValidatorIndex) {
        if let Some(score) = self.scores.get_mut(&index) {
            *score = score.saturating_sub(SCORE_PENALTY_LATE);
        }
    }

    /// Penalize equivocation — score goes to 0, validator will be ejected.
    pub fn penalize_equivocation(&mut self, index: ValidatorIndex) {
        if let Some(score) = self.scores.get_mut(&index) {
            *score = score.saturating_sub(SCORE_PENALTY_EQUIVOCATION);
        }
    }

    /// Get validators that should be ejected this epoch.
    /// Returns indices of validators below MIN_TRUST_SCORE
    /// plus the bottom EJECTION_RATE_BPS% by score.
    pub fn ejection_candidates(&self) -> Vec<ValidatorIndex> {
        let mut candidates: Vec<ValidatorIndex> = Vec::new();

        // 1. Anyone below minimum trust score
        for (&idx, &score) in &self.scores {
            if score < MIN_TRUST_SCORE {
                candidates.push(idx);
            }
        }

        // 2. Bottom N% by score (if we're at max validators)
        if self.scores.len() >= MAX_VALIDATORS {
            let mut sorted: Vec<(ValidatorIndex, u32)> =
                self.scores.iter().map(|(&k, &v)| (k, v)).collect();
            sorted.sort_by_key(|&(_, score)| score);

            let eject_count = (sorted.len() * EJECTION_RATE_BPS as usize) / 10_000;
            for &(idx, _) in sorted.iter().take(eject_count) {
                if !candidates.contains(&idx) {
                    candidates.push(idx);
                }
            }
        }

        candidates
    }

    /// Set a validator's trust score directly (for committee rotation migration).
    pub fn set_score(&mut self, index: ValidatorIndex, score: u32) {
        self.scores.insert(index, score.min(MAX_TRUST_SCORE));
    }

    /// Remove ejected validators.
    pub fn remove(&mut self, index: ValidatorIndex) {
        self.scores.remove(&index);
    }

    /// Number of tracked validators.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

impl Default for TrustScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_score() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        assert_eq!(ts.score(0), INITIAL_TRUST_SCORE);
    }

    #[test]
    fn reward_caps_at_max() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        for _ in 0..2000 {
            ts.reward_event(0);
        }
        assert_eq!(ts.score(0), MAX_TRUST_SCORE);
    }

    #[test]
    fn miss_penalty() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        ts.penalize_miss(0);
        assert_eq!(ts.score(0), INITIAL_TRUST_SCORE - SCORE_PENALTY_MISS);
    }

    #[test]
    fn equivocation_destroys_score() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        ts.penalize_equivocation(0);
        assert_eq!(ts.score(0), 0);
    }

    #[test]
    fn below_min_triggers_ejection() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        ts.register(1);

        // Drive validator 0 below minimum
        for _ in 0..100 {
            ts.penalize_miss(0);
        }

        let candidates = ts.ejection_candidates();
        assert!(candidates.contains(&0));
        assert!(!candidates.contains(&1));
    }

    #[test]
    fn score_never_goes_negative() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        for _ in 0..1000 {
            ts.penalize_miss(0);
        }
        assert_eq!(ts.score(0), 0);
    }

    #[test]
    fn set_score_direct() {
        let mut ts = TrustScorer::new();
        ts.set_score(0, 750);
        assert_eq!(ts.score(0), 750);

        // Capped at MAX_TRUST_SCORE
        ts.set_score(0, 5000);
        assert_eq!(ts.score(0), MAX_TRUST_SCORE);
    }

    #[test]
    fn set_score_then_modify() {
        let mut ts = TrustScorer::new();
        ts.set_score(0, 800);
        ts.penalize_miss(0);
        assert_eq!(ts.score(0), 800 - SCORE_PENALTY_MISS);
        ts.reward_event(0);
        assert_eq!(ts.score(0), 800 - SCORE_PENALTY_MISS + SCORE_REWARD_EVENT);
    }
}
