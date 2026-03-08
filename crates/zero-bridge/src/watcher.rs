//! Independent vault watcher service — CCIP Risk Management pattern.
//!
//! The watcher runs separately from the bridge service. It:
//!   - Monitors vault contracts for Deposited and Released events
//!   - Tracks cumulative withdrawals against circuit breaker thresholds
//!   - Detects anomalies (rapid large releases, unusual patterns)
//!   - Can call pause() on the vault via a PAUSER_ROLE key
//!   - CANNOT sign releases (no signing key, no coordinator)
//!
//! This separation ensures that a compromised bridge service cannot suppress
//! anomaly detection. The watcher is the "fire alarm" — simple, independent,
//! always watching.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Anomaly types the watcher can detect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anomaly {
    /// Cumulative releases exceeded normal tier threshold (20% of TVL in 24h)
    NormalTierExceeded {
        token: String,
        released: u64,
        total_locked: u64,
        pct_bps: u64,
    },
    /// Cumulative releases exceeded elevated tier threshold (50% of TVL in 24h)
    ElevatedTierExceeded {
        token: String,
        released: u64,
        total_locked: u64,
        pct_bps: u64,
    },
    /// Large single release (configurable threshold)
    LargeRelease {
        token: String,
        amount: u64,
        tx_hash: String,
    },
    /// Rapid successive releases (many releases in a short window)
    RapidReleases { count: usize, window_secs: u64 },
    /// Deposit-release mismatch: more released than deposited recently
    NetOutflow {
        token: String,
        deposited: u64,
        released: u64,
    },
}

/// Action the watcher takes in response to an anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherAction {
    /// Log the anomaly (low severity)
    Log,
    /// Alert (medium severity — could be normal elevated-tier usage)
    Alert,
    /// Pause the vault (high severity — suspected attack)
    Pause,
}

/// Configuration for the watcher's anomaly detection.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// Threshold for "large release" alert (in token units)
    pub large_release_threshold: u64,
    /// Number of releases in rapid_window_secs that triggers alert
    pub rapid_release_count: usize,
    /// Window for rapid release detection (seconds)
    pub rapid_window_secs: u64,
    /// Auto-pause when elevated tier (50%) exceeded?
    pub auto_pause_on_elevated: bool,
    /// Poll interval (milliseconds)
    pub poll_interval_ms: u64,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            large_release_threshold: 100_000_000, // 100 USDC (6 decimals)
            rapid_release_count: 10,
            rapid_window_secs: 300, // 5 minutes
            auto_pause_on_elevated: true,
            poll_interval_ms: 5000,
        }
    }
}

/// Per-token tracking state.
#[derive(Debug, Default)]
struct TokenTracker {
    /// Total released in current 24h window
    released_in_window: u64,
    /// Total deposited in current 24h window
    deposited_in_window: u64,
    /// Known total locked (from contract state)
    total_locked: u64,
    /// Timestamps of recent releases (for rapid-release detection)
    recent_release_times: Vec<u64>,
}

/// Vault watcher state.
pub struct VaultWatcher {
    config: WatcherConfig,
    /// Per-token tracking
    trackers: HashMap<String, TokenTracker>,
    /// Start of current 24h window
    window_start: u64,
    /// All detected anomalies (for reporting)
    anomalies: Vec<(u64, Anomaly, WatcherAction)>,
}

impl VaultWatcher {
    pub fn new(config: WatcherConfig) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self::new_with_start(config, now)
    }

    /// Create a watcher with a specific window start time (useful for tests).
    pub fn new_with_start(config: WatcherConfig, window_start: u64) -> Self {
        Self {
            config,
            trackers: HashMap::new(),
            window_start,
            anomalies: Vec::new(),
        }
    }

    /// Record a deposit event.
    pub fn record_deposit(&mut self, token: &str, amount: u64, now: u64) {
        self.maybe_reset_window(now);
        let tracker = self.trackers.entry(token.to_string()).or_default();
        tracker.deposited_in_window += amount;
    }

    /// Record a release event and check for anomalies.
    pub fn record_release(
        &mut self,
        token: &str,
        amount: u64,
        tx_hash: &str,
        now: u64,
    ) -> Vec<(Anomaly, WatcherAction)> {
        self.maybe_reset_window(now);
        let mut alerts = Vec::new();

        let tracker = self.trackers.entry(token.to_string()).or_default();
        tracker.released_in_window += amount;
        tracker.recent_release_times.push(now);

        // Prune old release times
        let cutoff = now.saturating_sub(self.config.rapid_window_secs);
        tracker.recent_release_times.retain(|&t| t >= cutoff);

        // Check: large single release
        if amount >= self.config.large_release_threshold {
            let anomaly = Anomaly::LargeRelease {
                token: token.to_string(),
                amount,
                tx_hash: tx_hash.to_string(),
            };
            alerts.push((anomaly, WatcherAction::Alert));
        }

        // Check: rapid successive releases
        if tracker.recent_release_times.len() >= self.config.rapid_release_count {
            let anomaly = Anomaly::RapidReleases {
                count: tracker.recent_release_times.len(),
                window_secs: self.config.rapid_window_secs,
            };
            alerts.push((anomaly, WatcherAction::Alert));
        }

        // Check: circuit breaker tiers (only if we know total_locked)
        if tracker.total_locked > 0 {
            let pct_bps =
                (tracker.released_in_window as u128 * 10_000 / tracker.total_locked as u128) as u64;

            if pct_bps > 5000 {
                // Elevated tier exceeded (>50%)
                let anomaly = Anomaly::ElevatedTierExceeded {
                    token: token.to_string(),
                    released: tracker.released_in_window,
                    total_locked: tracker.total_locked,
                    pct_bps,
                };
                let action = if self.config.auto_pause_on_elevated {
                    WatcherAction::Pause
                } else {
                    WatcherAction::Alert
                };
                alerts.push((anomaly, action));
            } else if pct_bps > 2000 {
                // Normal tier exceeded (>20%)
                let anomaly = Anomaly::NormalTierExceeded {
                    token: token.to_string(),
                    released: tracker.released_in_window,
                    total_locked: tracker.total_locked,
                    pct_bps,
                };
                alerts.push((anomaly, WatcherAction::Log));
            }
        }

        // Check: net outflow (only relevant when there have been deposits this window)
        if tracker.deposited_in_window > 0
            && tracker.released_in_window > tracker.deposited_in_window * 2
        {
            let anomaly = Anomaly::NetOutflow {
                token: token.to_string(),
                deposited: tracker.deposited_in_window,
                released: tracker.released_in_window,
            };
            alerts.push((anomaly, WatcherAction::Alert));
        }

        // Store anomalies
        for (anomaly, action) in &alerts {
            self.anomalies.push((now, anomaly.clone(), action.clone()));
        }

        alerts
    }

    /// Update known total locked for a token (from on-chain query).
    pub fn update_total_locked(&mut self, token: &str, total_locked: u64) {
        let tracker = self.trackers.entry(token.to_string()).or_default();
        tracker.total_locked = total_locked;
    }

    /// Reset the 24h window if enough time has passed.
    fn maybe_reset_window(&mut self, now: u64) {
        if now - self.window_start >= 86400 {
            for tracker in self.trackers.values_mut() {
                tracker.released_in_window = 0;
                tracker.deposited_in_window = 0;
            }
            self.window_start = now;
        }
    }

    /// Get all anomalies detected so far.
    pub fn anomalies(&self) -> &[(u64, Anomaly, WatcherAction)] {
        &self.anomalies
    }

    /// Get the number of anomalies requiring pause action.
    pub fn pause_required_count(&self) -> usize {
        self.anomalies
            .iter()
            .filter(|(_, _, action)| *action == WatcherAction::Pause)
            .count()
    }

    /// Get current tracking stats for a token.
    pub fn token_stats(&self, token: &str) -> Option<(u64, u64, u64)> {
        self.trackers
            .get(token)
            .map(|t| (t.released_in_window, t.deposited_in_window, t.total_locked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_watcher() -> VaultWatcher {
        VaultWatcher::new_with_start(
            WatcherConfig {
                large_release_threshold: 1_000_000, // 1 USDC
                rapid_release_count: 5,
                rapid_window_secs: 60,
                auto_pause_on_elevated: true,
                poll_interval_ms: 1000,
            },
            0,
        ) // Start window at 0 for deterministic tests
    }

    #[test]
    fn normal_release_no_anomaly() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 100_000_000); // 100 USDC locked
        let alerts = w.record_release("USDC", 100_000, "0xabc", 1000); // 0.1 USDC
        assert!(alerts.is_empty());
    }

    #[test]
    fn large_release_triggers_alert() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 100_000_000);
        let alerts = w.record_release("USDC", 5_000_000, "0xabc", 1000); // 5 USDC > 1 USDC threshold
        assert!(
            alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::LargeRelease { .. }))
        );
    }

    #[test]
    fn normal_tier_exceeded_logged() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000); // 10 USDC
        // Release 2.5 USDC = 25% > 20% normal tier
        let alerts = w.record_release("USDC", 2_500_000, "0xabc", 1000);
        assert!(alerts.iter().any(|(a, action)| {
            matches!(a, Anomaly::NormalTierExceeded { .. }) && *action == WatcherAction::Log
        }));
    }

    #[test]
    fn elevated_tier_triggers_pause() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000); // 10 USDC
        // Release 6 USDC = 60% > 50% elevated tier
        let alerts = w.record_release("USDC", 6_000_000, "0xabc", 1000);
        assert!(alerts.iter().any(|(a, action)| {
            matches!(a, Anomaly::ElevatedTierExceeded { .. }) && *action == WatcherAction::Pause
        }));
    }

    #[test]
    fn cumulative_releases_trigger_tier() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000); // 10 USDC
        // 3 releases of 0.8 USDC each = 2.4 USDC = 24% > 20%
        w.record_release("USDC", 800_000, "0x01", 1000);
        w.record_release("USDC", 800_000, "0x02", 1001);
        let alerts = w.record_release("USDC", 800_000, "0x03", 1002);
        assert!(
            alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::NormalTierExceeded { .. }))
        );
    }

    #[test]
    fn rapid_releases_detected() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 1_000_000_000); // 1000 USDC (so no tier alerts)
        for i in 0..4 {
            w.record_release("USDC", 100, &format!("0x{:02x}", i), 1000 + i);
        }
        // 5th release triggers rapid detection
        let alerts = w.record_release("USDC", 100, "0x05", 1004);
        assert!(
            alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::RapidReleases { .. }))
        );
    }

    #[test]
    fn window_resets_after_24h() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000);
        w.record_release("USDC", 1_500_000, "0x01", 1000); // 15%
        assert_eq!(w.token_stats("USDC").unwrap().0, 1_500_000);

        // 24h later — window should reset
        let alerts = w.record_release("USDC", 500_000, "0x02", 1000 + 86401);
        // After reset, only 500_000 released = 5%, no tier alert
        assert!(
            !alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::NormalTierExceeded { .. }))
        );
        assert_eq!(w.token_stats("USDC").unwrap().0, 500_000);
    }

    #[test]
    fn net_outflow_detected() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 1_000_000_000); // Large TVL to avoid tier alerts
        w.record_deposit("USDC", 100_000, 1000); // Small deposit
        // Release > 2x deposits
        let alerts = w.record_release("USDC", 500_000, "0x01", 1001);
        assert!(
            alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::NetOutflow { .. }))
        );
    }

    #[test]
    fn deposits_tracked() {
        let mut w = default_watcher();
        w.record_deposit("USDC", 5_000_000, 1000);
        w.record_deposit("USDC", 3_000_000, 1001);
        let (_, deposited, _) = w.token_stats("USDC").unwrap();
        assert_eq!(deposited, 8_000_000);
    }

    #[test]
    fn pause_count_tracks_severe_anomalies() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000);
        w.record_release("USDC", 6_000_000, "0x01", 1000); // >50% = pause
        assert_eq!(w.pause_required_count(), 1);
    }

    #[test]
    fn multiple_tokens_independent() {
        let mut w = default_watcher();
        w.update_total_locked("USDC", 10_000_000);
        w.update_total_locked("USDT", 20_000_000);
        let usdc_alerts = w.record_release("USDC", 2_500_000, "0x01", 1000); // 25% of USDC
        let usdt_alerts = w.record_release("USDT", 500_000, "0x02", 1000); // 2.5% of USDT (below thresholds)
        // USDC should trigger normal tier, USDT should not
        assert!(
            usdc_alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::NormalTierExceeded { .. }))
        );
        assert!(
            !usdt_alerts
                .iter()
                .any(|(a, _)| matches!(a, Anomaly::NormalTierExceeded { .. }))
        );
        // Per-token tracking is independent
        let (usdc_released, _, _) = w.token_stats("USDC").unwrap();
        let (usdt_released, _, _) = w.token_stats("USDT").unwrap();
        assert_eq!(usdc_released, 2_500_000);
        assert_eq!(usdt_released, 500_000);
    }
}
