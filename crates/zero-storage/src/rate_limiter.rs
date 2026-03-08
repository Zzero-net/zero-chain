use std::collections::HashMap;

use zero_types::{PubKey, TimestampMs, params::MAX_TX_PER_ACCOUNT_PER_SEC};

/// Per-account rate limiter using a sliding window.
///
/// Tracks the number of transactions per account within a 1-second window.
/// Rejects transactions that exceed MAX_TX_PER_ACCOUNT_PER_SEC.
pub struct RateLimiter {
    /// Map from account pubkey to (window_start_ms, count_in_window).
    windows: HashMap<PubKey, (TimestampMs, u32)>,
    max_per_sec: u32,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            windows: HashMap::new(),
            max_per_sec: MAX_TX_PER_ACCOUNT_PER_SEC,
        }
    }

    /// Check if an account can send a transaction at the given timestamp.
    /// Returns Ok(()) if allowed, Err(current_rate) if rate limited.
    pub fn check(&mut self, account: &PubKey, now_ms: TimestampMs) -> Result<(), u32> {
        let entry = self.windows.entry(*account).or_insert((now_ms, 0));

        // If we're in a new window (>1 second since window start), reset
        if now_ms >= entry.0 + 1000 {
            entry.0 = now_ms;
            entry.1 = 0;
        }

        if entry.1 >= self.max_per_sec {
            return Err(entry.1);
        }

        entry.1 += 1;
        Ok(())
    }

    /// Clean up old entries (call periodically to prevent memory growth).
    pub fn cleanup(&mut self, now_ms: TimestampMs) {
        self.windows
            .retain(|_, (window_start, _)| now_ms < *window_start + 10_000);
    }

    pub fn len(&self) -> usize {
        self.windows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_under_limit() {
        let mut rl = RateLimiter::new();
        let key = [1u8; 32];
        for i in 0..MAX_TX_PER_ACCOUNT_PER_SEC {
            assert!(rl.check(&key, 1000).is_ok(), "failed at tx {}", i);
        }
    }

    #[test]
    fn rejects_over_limit() {
        let mut rl = RateLimiter::new();
        let key = [1u8; 32];
        for _ in 0..MAX_TX_PER_ACCOUNT_PER_SEC {
            rl.check(&key, 1000).unwrap();
        }
        assert!(rl.check(&key, 1000).is_err());
    }

    #[test]
    fn resets_after_window() {
        let mut rl = RateLimiter::new();
        let key = [1u8; 32];
        for _ in 0..MAX_TX_PER_ACCOUNT_PER_SEC {
            rl.check(&key, 1000).unwrap();
        }
        // New window (1 second later)
        assert!(rl.check(&key, 2001).is_ok());
    }

    #[test]
    fn independent_accounts() {
        let mut rl = RateLimiter::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        for _ in 0..MAX_TX_PER_ACCOUNT_PER_SEC {
            rl.check(&key1, 1000).unwrap();
        }
        // key2 should still be allowed
        assert!(rl.check(&key2, 1000).is_ok());
    }

    #[test]
    fn cleanup_removes_old() {
        let mut rl = RateLimiter::new();
        let key = [1u8; 32];
        rl.check(&key, 1000).unwrap();
        assert_eq!(rl.len(), 1);
        rl.cleanup(20_000);
        assert_eq!(rl.len(), 0);
    }
}
