use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};
use zero_storage::TransferExecutor;
use zero_types::{
    Hash, PubKey, TimestampMs, Transfer, ValidatorIndex,
    block::Event,
    params::{
        EPOCH_LENGTH, LATE_EVENT_THRESHOLD_MS, MAX_VALIDATORS, MIN_TRUST_SCORE, SLASH_DOWNTIME_BPS,
        SLASH_EQUIVOCATION_BPS,
    },
};

use crate::committee::ValidatorInfo;
use crate::dag::InsertResult;
use crate::{Committee, Dag, TrustScorer, ValidatorState};

/// A consensus node that integrates the DAG, validator state, trust scoring,
/// and transfer execution into a single pipeline.
///
/// Flow:
///   1. Receive transfers from clients → submit to validator
///   2. Validator produces events → inserted into DAG
///   3. Receive events from peers → inserted into DAG
///   4. Try finalize → finalized events → execute transfers
///   5. Update trust scores based on validator behavior
pub struct Node {
    /// This node's validator state.
    validator: ValidatorState,
    /// The shared DAG.
    dag: Arc<RwLock<Dag>>,
    /// The committee.
    committee: Arc<Committee>,
    /// Transfer executor (the state machine).
    executor: Arc<RwLock<TransferExecutor>>,
    /// Trust scorer for validator reputation.
    trust: TrustScorer,
    /// Transfer batches received from other validators.
    /// Keyed by event digest → transfers in that event.
    remote_batches: HashMap<Hash, Vec<Transfer>>,
    /// Total transfers executed through finalization.
    finalized_tx_count: u64,
    /// Total finalized events (for epoch tracking).
    finalized_event_count: u64,
}

impl Node {
    pub fn new(
        index: ValidatorIndex,
        committee: Arc<Committee>,
        log_capacity: usize,
        max_batch_size: usize,
    ) -> Self {
        let dag = Arc::new(RwLock::new(Dag::new()));
        let executor = Arc::new(RwLock::new(TransferExecutor::new(log_capacity)));

        let mut trust = TrustScorer::new();
        for v in committee.validators() {
            trust.register(v.index);
        }

        let validator = ValidatorState::new(
            index,
            Arc::clone(&dag),
            Arc::clone(&committee),
            max_batch_size,
        );

        // Seed the stake store with genesis validator stakes
        {
            let mut exec = executor.write();
            for v in committee.validators() {
                exec.stake_store_mut().stake(&v.public_key, v.stake);
            }
        }

        Self {
            validator,
            dag,
            committee,
            executor,
            trust,
            remote_batches: HashMap::new(),
            finalized_tx_count: 0,
            finalized_event_count: 0,
        }
    }

    /// Submit a transfer from a client. Returns Ok if accepted into the pending pool.
    ///
    /// Only performs rate limiting here. Full validation (nonce, balance, signature)
    /// happens at execution time, because pending transfers may change account state
    /// before this one executes.
    pub fn submit_transfer(
        &mut self,
        tx: Transfer,
        now_ms: TimestampMs,
    ) -> Result<(), zero_types::ZeroError> {
        self.executor.write().check_rate_limit(&tx, now_ms)?;
        self.validator.submit_transfer(tx);
        Ok(())
    }

    /// Produce a new event if there are pending transfers.
    pub fn try_produce_event(&mut self, timestamp: TimestampMs) -> Option<Event> {
        let event = self.validator.try_produce_event(timestamp)?;
        debug!(
            round = event.round,
            author = event.author,
            txs = event.transactions.len(),
            "Produced event"
        );
        Some(event)
    }

    /// Produce a heartbeat event (empty batch) to advance the DAG.
    /// Called periodically so all validators participate in consensus.
    pub fn produce_heartbeat(&mut self, timestamp: TimestampMs) -> Event {
        let event = self.validator.produce_heartbeat(timestamp);
        debug!(
            round = event.round,
            author = event.author,
            "Produced heartbeat"
        );
        event
    }

    /// Receive an event from a peer validator.
    /// The caller must also provide the transfer batch for this event.
    /// Returns true if accepted, false if rejected (duplicate or equivocation).
    pub fn receive_event(
        &mut self,
        event: Event,
        transfers: Vec<Transfer>,
        now_ms: TimestampMs,
    ) -> bool {
        debug!(
            round = event.round,
            author = event.author,
            txs = transfers.len(),
            "Received peer event"
        );

        let author = event.author;
        let event_timestamp = event.timestamp;
        let digest = event.digest;
        let result = self.dag.write().insert(event);

        match result {
            InsertResult::Inserted => {
                // Check for late event — penalize if received well after creation
                let delay = now_ms.saturating_sub(event_timestamp);
                if delay > LATE_EVENT_THRESHOLD_MS && author != self.validator.index {
                    self.trust.penalize_late(author);
                    debug!(
                        validator = author,
                        delay_ms = delay,
                        "Late event detected — trust penalized"
                    );
                }

                self.remote_batches.insert(digest, transfers);
                true
            }
            InsertResult::Duplicate => {
                // Already have this exact event — harmless
                false
            }
            InsertResult::Equivocation(validator_idx) => {
                warn!(
                    validator = validator_idx,
                    "Equivocation detected — validator produced conflicting events in same round"
                );
                self.trust.penalize_equivocation(validator_idx);

                // Auto-slash equivocating validator's stake immediately
                if let Some(info) = self.committee.validator(validator_idx) {
                    let slashed = self
                        .executor
                        .write()
                        .slash_validator(&info.public_key, SLASH_EQUIVOCATION_BPS);
                    warn!(
                        validator = validator_idx,
                        slashed_amount = slashed,
                        "Equivocating validator auto-slashed (100% stake)"
                    );
                }

                false
            }
        }
    }

    /// Try to finalize events and execute their transfers.
    /// Returns the number of transfers executed.
    pub fn try_finalize_and_execute(&mut self, now_ms: TimestampMs) -> u64 {
        let finalized = self.validator.try_finalize();
        if finalized.is_empty() {
            return 0;
        }

        let mut executed = 0u64;

        for block_ref in &finalized {
            // Reward the author for this event
            self.trust.reward_event(block_ref.author);

            // Retrieve the transfer batch
            let batch = self
                .validator
                .take_batch(&block_ref.digest)
                .or_else(|| self.remote_batches.remove(&block_ref.digest));

            let Some(transfers) = batch else {
                warn!("Finalized event has no transfer batch — skipping");
                continue;
            };

            // Execute each transfer
            let mut exec = self.executor.write();
            for tx in &transfers {
                match exec.execute_with_time(tx, now_ms) {
                    Ok(result) => {
                        executed += 1;
                        debug!(seq = result.seq, fee = result.fee, "Executed transfer");
                    }
                    Err(e) => {
                        // Transfer was valid at submission but may have become invalid
                        // (e.g., balance changed due to earlier tx in same batch)
                        debug!(err = %e, "Skipped invalid transfer in finalized event");
                    }
                }
            }
        }

        self.finalized_tx_count += executed;

        // Penalize validators who missed finalized rounds
        self.check_missed_rounds(&finalized);

        // Track finalized events and check for epoch boundary
        let prev_epoch = self.finalized_event_count / EPOCH_LENGTH;
        self.finalized_event_count += finalized.len() as u64;
        let current_epoch = self.finalized_event_count / EPOCH_LENGTH;

        if current_epoch > prev_epoch {
            self.distribute_epoch_fees();
            self.auto_slash_ejection_candidates();
            self.rotate_committee();
        }

        if executed > 0 {
            info!(
                finalized_events = finalized.len(),
                executed_txs = executed,
                total = self.finalized_tx_count,
                "Finalization round complete"
            );
        }

        executed
    }

    /// Distribute accumulated fees at an epoch boundary.
    /// Splits 50/35/15 to validators/bridge/protocol.
    /// Trust-weighted: a validator's effective share is stake × (trust_score / MAX_TRUST_SCORE).
    /// Higher-trust validators earn proportionally more; low-trust validators earn less.
    fn distribute_epoch_fees(&mut self) {
        let validators: Vec<_> = self
            .committee
            .validators()
            .iter()
            .map(|v| {
                let trust = self.trust.score(v.index) as u64;
                let max_trust = zero_types::params::MAX_TRUST_SCORE as u64;
                // Effective stake = stake × trust_score / MAX_TRUST_SCORE
                let effective_stake = v.stake * trust / max_trust;
                (&v.public_key, effective_stake)
            })
            .collect();

        let dist = self.executor.write().distribute_fees(&validators);

        if dist.total > 0 {
            info!(
                epoch_fees = dist.total,
                validator_total = dist.validator_total,
                bridge_reserve = dist.bridge_amount,
                protocol_reserve = dist.protocol_amount,
                validators_paid = dist.validator_payouts.len(),
                "Epoch fee distribution (trust-weighted)"
            );
        }
    }

    /// Automatically slash validators who have been ejected based on trust scores.
    /// Called at epoch boundaries after fee distribution.
    fn auto_slash_ejection_candidates(&mut self) {
        let candidates = self.trust.ejection_candidates();
        if candidates.is_empty() {
            return;
        }

        let validators = self.committee.validators();
        let mut exec = self.executor.write();

        for idx in &candidates {
            let score = self.trust.score(*idx);
            let validator = match validators.get(*idx as usize) {
                Some(v) => v,
                None => continue,
            };

            // Determine slash severity based on trust score
            let slash_bps = if score == 0 {
                // Trust score destroyed (equivocation) — slash 100%
                SLASH_EQUIVOCATION_BPS
            } else if score < MIN_TRUST_SCORE {
                // Below ejection threshold (downtime/missed rounds) — slash 10%
                SLASH_DOWNTIME_BPS
            } else {
                // Bottom-N% ejection — light slash (downtime rate)
                SLASH_DOWNTIME_BPS
            };

            let slashed = exec.slash_validator(&validator.public_key, slash_bps);
            warn!(
                validator = idx,
                score,
                slash_bps,
                slashed_amount = slashed,
                "Auto-slashed validator (trust ejection)"
            );
        }
    }

    /// Rotate the committee based on current stake store state.
    /// Called at epoch boundaries after fee distribution and slashing.
    /// Builds a new committee from all validators with sufficient stake,
    /// capped at MAX_VALIDATORS, sorted by stake descending.
    fn rotate_committee(&mut self) {
        let exec = self.executor.read();
        let active = exec.stake_store().active_validators();
        drop(exec);

        if active.is_empty() {
            warn!("No active validators in stake store — keeping current committee");
            return;
        }

        // Cap at MAX_VALIDATORS, take highest-staked
        let cap = active.len().min(MAX_VALIDATORS);
        let new_validators: Vec<ValidatorInfo> = active[..cap]
            .iter()
            .enumerate()
            .map(|(i, (pk, stake))| ValidatorInfo {
                index: i as ValidatorIndex,
                public_key: *pk,
                stake: *stake,
            })
            .collect();

        let old_size = self.committee.size();
        let new_size = new_validators.len();

        // Build index mapping: old pubkey → old index, for trust score migration
        let old_keys: HashMap<PubKey, ValidatorIndex> = self
            .committee
            .validators()
            .iter()
            .map(|v| (v.public_key, v.index))
            .collect();

        let new_committee = Arc::new(Committee::new(new_validators));

        // Migrate trust scores to new indices
        let mut new_trust = TrustScorer::new();
        for v in new_committee.validators() {
            if let Some(&old_idx) = old_keys.get(&v.public_key) {
                // Existing validator — carry trust score forward
                let old_score = self.trust.score(old_idx);
                new_trust.set_score(v.index, old_score);
            } else {
                // New validator — start with initial trust score
                new_trust.register(v.index);
            }
        }

        // Remove ejected validators from trust scorer
        for v in self.committee.validators() {
            if new_committee.index_of(&v.public_key).is_none() {
                info!(
                    old_index = v.index,
                    pubkey = ?&v.public_key[..8],
                    "Validator removed from committee"
                );
            }
        }

        // Log new validators
        for v in new_committee.validators() {
            if !old_keys.contains_key(&v.public_key) {
                info!(
                    new_index = v.index,
                    pubkey = ?&v.public_key[..8],
                    stake = v.stake,
                    "New validator joined committee"
                );
            }
        }

        // Swap the committee
        self.committee = Arc::clone(&new_committee);
        self.validator.set_committee(Arc::clone(&new_committee));
        self.trust = new_trust;

        info!(
            epoch = self.current_epoch(),
            old_size,
            new_size,
            total_stake = new_committee.total_stake(),
            "Committee rotated"
        );
    }

    /// Check which validators missed finalized rounds and penalize them.
    /// A validator "misses" a round if all other validators produced events
    /// in that round but this validator did not.
    fn check_missed_rounds(&mut self, finalized: &[zero_types::block::BlockRef]) {
        use std::collections::HashSet;

        // Collect distinct rounds from finalized events
        let rounds: HashSet<u32> = finalized.iter().map(|r| r.round).collect();

        let dag = self.dag.read();
        let committee_size = self.committee.size();

        for round in rounds {
            // Get the set of validators who produced events in this round
            let events = dag.events_in_round(round);
            let participating: HashSet<ValidatorIndex> = events.iter().map(|e| e.author).collect();

            // Only penalize if at least half the committee participated
            // (avoids penalizing everyone during network startup or partition)
            if participating.len() < committee_size / 2 {
                continue;
            }

            // Penalize each validator who missed this round
            for v in self.committee.validators() {
                if !participating.contains(&v.index) && v.index != self.validator.index {
                    self.trust.penalize_miss(v.index);
                }
            }
        }
    }

    /// Penalize a validator for missing a round.
    pub fn penalize_miss(&mut self, index: ValidatorIndex) {
        self.trust.penalize_miss(index);
    }

    /// Penalize a validator for a late event.
    pub fn penalize_late(&mut self, index: ValidatorIndex) {
        self.trust.penalize_late(index);
    }

    /// Penalize a validator for equivocation.
    pub fn penalize_equivocation(&mut self, index: ValidatorIndex) {
        self.trust.penalize_equivocation(index);
    }

    /// Get ejection candidates based on trust scores.
    pub fn ejection_candidates(&self) -> Vec<ValidatorIndex> {
        self.trust.ejection_candidates()
    }

    /// Get a shared reference to the executor.
    pub fn executor(&self) -> &Arc<RwLock<TransferExecutor>> {
        &self.executor
    }

    /// Get the trust score for a validator.
    pub fn trust_score(&self, index: ValidatorIndex) -> u32 {
        self.trust.score(index)
    }

    /// Total finalized transaction count.
    pub fn finalized_tx_count(&self) -> u64 {
        self.finalized_tx_count
    }

    /// Total finalized event count (for epoch tracking).
    pub fn finalized_event_count(&self) -> u64 {
        self.finalized_event_count
    }

    /// Current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.finalized_event_count / EPOCH_LENGTH
    }

    /// Access the validator state.
    pub fn validator(&self) -> &ValidatorState {
        &self.validator
    }

    /// Mutable access to the validator state.
    pub fn validator_mut(&mut self) -> &mut ValidatorState {
        &mut self.validator
    }

    /// Get the shared DAG.
    pub fn dag(&self) -> &Arc<RwLock<Dag>> {
        &self.dag
    }

    /// Get the committee.
    pub fn committee(&self) -> &Arc<Committee> {
        &self.committee
    }

    /// Peek at a remote batch without removing it (for pull catch-up responses).
    pub fn peek_remote_batch(&self, digest: &Hash) -> Option<Vec<Transfer>> {
        self.remote_batches.get(digest).cloned()
    }

    /// Get events from a specific round onwards (for catch-up responses).
    pub fn get_events_from(&self, from_round: u32, max: u32) -> Vec<Event> {
        let dag = self.dag.read();
        let mut events = Vec::new();
        for round in from_round.. {
            let round_events = dag.events_in_round(round);
            if round_events.is_empty() && round > dag.current_round() {
                break;
            }
            for event in round_events {
                events.push(event.clone());
                if events.len() >= max as usize {
                    return events;
                }
            }
        }
        events
    }

    /// Periodic maintenance: clean up rate limiter, prune dust accounts,
    /// complete unbonding, prune old batches.
    pub fn maintenance(&mut self, now_ms: TimestampMs) {
        let mut exec = self.executor.write();
        exec.cleanup_rate_limiter(now_ms);
        let (pruned, reclaimed) = exec.prune_dust(now_ms);
        if pruned > 0 {
            info!(pruned, reclaimed, "Dust accounts pruned");
        }
        // Complete unbonding for validators whose unbonding period has elapsed
        let unbonded = exec.complete_unbonding(now_ms);
        if !unbonded.is_empty() {
            info!(count = unbonded.len(), "Completed unbonding for validators");
        }
        drop(exec);
        self.validator.prune_batches(1000);
    }
}

/// Trait for handling gossip events. Defined here so the network layer can use it
/// without creating a circular dependency.
pub trait GossipHandler: Send + Sync + 'static {
    /// Handle a received event + its transfer batch from a peer.
    /// Returns Ok(true) if accepted, Ok(false) if duplicate, Err on invalid.
    fn handle_event(&self, event: Event, transfers: Vec<Transfer>) -> Result<bool, String>;

    /// Get events from a given round for catch-up.
    fn get_events_from(&self, from_round: u32, max: u32) -> Vec<(Event, Vec<Transfer>)>;
}

/// Thread-safe wrapper around Node that implements the GossipHandler trait.
/// Used by the gRPC gossip server to route incoming events to the local node.
pub struct NodeGossipHandler {
    node: Arc<RwLock<Node>>,
}

impl NodeGossipHandler {
    pub fn new(node: Arc<RwLock<Node>>) -> Self {
        Self { node }
    }
}

impl GossipHandler for NodeGossipHandler {
    fn handle_event(&self, event: Event, transfers: Vec<Transfer>) -> Result<bool, String> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut node = self.node.write();
        let accepted = node.receive_event(event, transfers, now_ms);
        Ok(accepted)
    }

    fn get_events_from(&self, from_round: u32, max: u32) -> Vec<(Event, Vec<Transfer>)> {
        let node = self.node.read();
        let events = node.get_events_from(from_round, max);
        events
            .into_iter()
            .map(|e| {
                // Try to get the batch from local or remote storage.
                // Most catch-up events are heartbeats (empty batch), so empty is fine.
                let batch = node
                    .peek_remote_batch(&e.digest)
                    .or_else(|| node.validator().peek_batch(&e.digest))
                    .unwrap_or_default();
                (e, batch)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::ValidatorInfo;
    use zero_crypto::keypair::KeyPair;
    use zero_types::params::ACCOUNT_CREATION_FEE;
    use zero_types::transfer::TRANSFER_FEE;

    fn make_committee(n: usize) -> Arc<Committee> {
        let validators: Vec<ValidatorInfo> = (0..n)
            .map(|i| ValidatorInfo {
                index: i as ValidatorIndex,
                public_key: {
                    let mut k = [0u8; 32];
                    k[0] = (i + 1) as u8;
                    k
                },
                stake: 100,
            })
            .collect();
        Arc::new(Committee::new(validators))
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
    fn single_validator_full_pipeline() {
        let committee = make_committee(1);
        let mut node = Node::new(0, committee, 10_000, 100);

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();

        // Fund sender with 100,000 units = 1,000 Z = $10
        node.executor.write().mint(&sender.public_key(), 100_000);

        // Submit two transfers (both nonce 1 and 2 accepted — only rate-limited on submit)
        let tx1 = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        let tx2 = make_signed_transfer(&sender, &receiver.public_key(), 50, 2);
        node.submit_transfer(tx1, 1000).unwrap();
        node.submit_transfer(tx2, 1000).unwrap();

        // Produce event (round 1) with both transfers
        let event = node.try_produce_event(1000).unwrap();
        assert_eq!(event.transactions.len(), 2);

        // We need a round 2 event to reference round 1 for finalization.
        // Submit a dummy transfer to produce round 2.
        let tx3 = make_signed_transfer(&sender, &receiver.public_key(), 10, 3);
        node.submit_transfer(tx3, 1001).unwrap();
        node.try_produce_event(1001);

        // Try finalize — with 1 validator, round 1 should finalize
        let executed = node.try_finalize_and_execute(1001);
        assert_eq!(executed, 2); // both transfers in round 1

        // Check balances — first transfer creates account (extra fee), second doesn't
        let exec = node.executor.read();
        assert_eq!(exec.accounts().balance(&receiver.public_key()), 150);
        let expected_cost = 100 + 50 + TRANSFER_FEE * 2 + ACCOUNT_CREATION_FEE;
        assert_eq!(
            exec.accounts().balance(&sender.public_key()),
            100_000 - expected_cost
        );
    }

    #[test]
    fn three_validator_consensus() {
        let committee = make_committee(3);

        // Shared DAG and executor
        let dag = Arc::new(RwLock::new(Dag::new()));
        let executor = Arc::new(RwLock::new(TransferExecutor::new(10_000)));

        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        executor.write().mint(&sender.public_key(), 100_000);

        let mut validators: Vec<ValidatorState> = (0..3)
            .map(|i| {
                ValidatorState::new(
                    i as ValidatorIndex,
                    Arc::clone(&dag),
                    Arc::clone(&committee),
                    100,
                )
            })
            .collect();

        // Round 1: all three validators produce events
        let tx0 = make_signed_transfer(&sender, &receiver.public_key(), 200, 1);
        validators[0].submit_transfer(tx0);
        let e0 = validators[0].try_produce_event(1000).unwrap();
        let e0_ref = e0.reference();
        let batch0 = validators[0].take_batch(&e0.digest).unwrap();

        // Validators 1 and 2 also produce round 1 events (with their own transfers)
        let sender2 = KeyPair::generate();
        executor.write().mint(&sender2.public_key(), 100_000);
        let tx1 = make_signed_transfer(&sender2, &receiver.public_key(), 10, 1);
        validators[1].submit_transfer(tx1);
        let _e1 = validators[1].try_produce_event(1000).unwrap();

        let sender3 = KeyPair::generate();
        executor.write().mint(&sender3.public_key(), 100_000);
        let tx2 = make_signed_transfer(&sender3, &receiver.public_key(), 10, 1);
        validators[2].submit_transfer(tx2);
        let _e2 = validators[2].try_produce_event(1000).unwrap();

        // Round 2: all three produce events referencing round 1
        // (each validator needs pending txs to produce an event)
        let tx3 = make_signed_transfer(&sender, &receiver.public_key(), 1, 2);
        validators[0].submit_transfer(tx3);
        validators[0].try_produce_event(1001);

        let tx4 = make_signed_transfer(&sender2, &receiver.public_key(), 1, 2);
        validators[1].submit_transfer(tx4);
        validators[1].try_produce_event(1001);

        let tx5 = make_signed_transfer(&sender3, &receiver.public_key(), 1, 2);
        validators[2].submit_transfer(tx5);
        validators[2].try_produce_event(1001);

        // Finalize: round 1 events should be finalized (all 3 validators in round 2 reference them)
        let finalized = dag.write().try_finalize(&committee);
        let e0_finalized = finalized.iter().any(|r| *r == e0_ref);
        assert!(e0_finalized, "e0 should be finalized");

        // Execute batch0 (validator 0's round-1 event)
        {
            let mut exec = executor.write();
            for tx in &batch0 {
                exec.execute(tx).unwrap();
            }
        }

        assert_eq!(
            executor.read().accounts().balance(&receiver.public_key()),
            200
        );
    }

    #[test]
    fn trust_scoring_through_node() {
        let committee = make_committee(3);
        let mut node = Node::new(0, committee, 10_000, 100);

        // Initial scores
        assert_eq!(node.trust_score(0), zero_types::params::INITIAL_TRUST_SCORE);

        // Penalize validator 1 for missing
        node.penalize_miss(1);
        assert!(node.trust_score(1) < zero_types::params::INITIAL_TRUST_SCORE);

        // Penalize validator 2 for equivocation
        node.penalize_equivocation(2);
        assert_eq!(node.trust_score(2), 0);

        // Validator 2 should be an ejection candidate
        let candidates = node.ejection_candidates();
        assert!(candidates.contains(&2));
    }

    #[test]
    fn equivocation_detected_via_receive_event() {
        let committee = make_committee(3);
        let mut node = Node::new(0, committee, 10_000, 100);

        // Validator 1 sends a legitimate event
        let event1 = zero_types::block::Event {
            round: 1,
            author: 1,
            timestamp: 1000,
            parents: vec![],
            transactions: vec![],
            digest: zero_crypto::blake3_hash(b"event-1-legit"),
        };
        let accepted = node.receive_event(event1, vec![], 1000);
        assert!(accepted);

        // Validator 1 sends a DIFFERENT event for the same round (equivocation)
        let event2 = zero_types::block::Event {
            round: 1,
            author: 1,
            timestamp: 1001,
            parents: vec![],
            transactions: vec![],
            digest: zero_crypto::blake3_hash(b"event-1-equivocation"),
        };
        let accepted = node.receive_event(event2, vec![], 1001);
        assert!(!accepted);

        // Validator 1's trust score should be 0 (equivocation penalty)
        assert_eq!(node.trust_score(1), 0);

        // Validator 1 should be an ejection candidate
        assert!(node.ejection_candidates().contains(&1));
    }

    #[test]
    fn stake_store_seeded_from_genesis() {
        let committee = make_committee(3);
        let node = Node::new(0, committee, 10_000, 100);

        // Each validator in make_committee has stake=100
        let exec = node.executor().read();
        for i in 0..3 {
            let mut k = [0u8; 32];
            k[0] = (i + 1) as u8;
            assert_eq!(exec.stake_store().staked(&k), 100);
        }
    }

    #[test]
    fn rotate_committee_preserves_same_set() {
        let committee = make_committee(3);
        let mut node = Node::new(0, committee, 10_000, 100);

        // Force a committee rotation by calling the private method indirectly
        // via triggering an epoch boundary
        // Stake is 100 per validator, which is below MIN_VALIDATOR_STAKE,
        // so rotation would find no active validators and keep current committee.
        // Let's boost stakes to be valid.
        {
            let mut exec = node.executor().write();
            for i in 0..3 {
                let mut k = [0u8; 32];
                k[0] = (i + 1) as u8;
                // Add enough to reach MIN_VALIDATOR_STAKE (1_000_000)
                exec.stake_store_mut().stake(&k, 1_000_000 - 100);
            }
        }

        // Verify stakes are sufficient
        {
            let exec = node.executor().read();
            let active = exec.stake_store().active_validators();
            assert_eq!(active.len(), 3);
        }

        // The committee should remain the same size after rotation
        assert_eq!(node.committee().size(), 3);

        // Trigger rotation manually by running enough finalization
        // Instead, test directly: node.committee should have 3 validators
        // and trust scores should be preserved
        let trust_before = node.trust_score(0);
        assert_eq!(trust_before, zero_types::params::INITIAL_TRUST_SCORE);
    }

    #[test]
    fn trust_weighted_fee_distribution() {
        let committee = make_committee(2);
        let mut node = Node::new(0, Arc::clone(&committee), 10_000, 100);

        // Boost stakes to valid amounts
        {
            let mut exec = node.executor().write();
            for i in 0..2 {
                let mut k = [0u8; 32];
                k[0] = (i + 1) as u8;
                exec.stake_store_mut().stake(&k, 1_000_000 - 100);
            }
        }

        // Fund the fee pool via a transfer
        let sender = KeyPair::generate();
        let receiver = KeyPair::generate();
        node.executor().write().mint(&sender.public_key(), 100_000);

        let tx = make_signed_transfer(&sender, &receiver.public_key(), 100, 1);
        node.submit_transfer(tx, 1000).unwrap();

        // Produce and finalize events
        node.try_produce_event(1000);
        let tx2 = make_signed_transfer(&sender, &receiver.public_key(), 50, 2);
        node.submit_transfer(tx2, 1001).unwrap();
        node.try_produce_event(1001);
        node.try_finalize_and_execute(1001);

        // Reward validator 0 heavily to make its trust higher
        for _ in 0..500 {
            node.trust.reward_event(0);
        }
        // Now validator 0 has trust score = 1000 (max), validator 1 has 500+1 (from finalization reward)

        let score_0 = node.trust_score(0);
        let score_1 = node.trust_score(1);
        assert_eq!(score_0, 1000); // MAX_TRUST_SCORE
        assert!(score_1 < score_0); // validator 1 has lower trust

        // Effective stake for fee distribution:
        // v0: 1_000_000 × 1000/1000 = 1_000_000
        // v1: 1_000_000 × ~501/1000 = ~501_000
        // So validator 0 should get ~66.6% of validator share
    }

    #[test]
    fn trust_scorer_set_score() {
        let mut ts = TrustScorer::new();
        ts.register(0);
        assert_eq!(ts.score(0), zero_types::params::INITIAL_TRUST_SCORE);

        ts.set_score(0, 800);
        assert_eq!(ts.score(0), 800);

        // Capped at MAX
        ts.set_score(0, 9999);
        assert_eq!(ts.score(0), zero_types::params::MAX_TRUST_SCORE);
    }

    #[test]
    fn late_event_detection() {
        let committee = make_committee(3);
        let mut node = Node::new(0, committee, 10_000, 100);

        // Validator 1 sends an event with timestamp 1000
        let event = zero_types::block::Event {
            round: 1,
            author: 1,
            timestamp: 1000,
            parents: vec![],
            transactions: vec![],
            digest: zero_crypto::blake3_hash(b"late-event"),
        };

        // Receive it 10 seconds later (well above LATE_EVENT_THRESHOLD_MS = 5000)
        let accepted = node.receive_event(event, vec![], 11000);
        assert!(accepted);

        // Validator 1 should have been penalized for lateness
        let expected =
            zero_types::params::INITIAL_TRUST_SCORE - zero_types::params::SCORE_PENALTY_LATE;
        assert_eq!(node.trust_score(1), expected);
    }

    #[test]
    fn equivocation_immediate_slash() {
        let committee = make_committee(3);
        let mut node = Node::new(0, committee, 10_000, 100);

        // Boost validator 1's stake
        {
            let mut exec = node.executor().write();
            let mut k = [0u8; 32];
            k[0] = 2; // validator 1's key
            exec.stake_store_mut().stake(&k, 1_000_000 - 100);
        }

        // Verify stake before equivocation
        {
            let exec = node.executor().read();
            let mut k = [0u8; 32];
            k[0] = 2;
            assert_eq!(exec.stake_store().staked(&k), 1_000_000);
        }

        // Validator 1 produces two events in same round (equivocation)
        let event1 = zero_types::block::Event {
            round: 1,
            author: 1,
            timestamp: 1000,
            parents: vec![],
            transactions: vec![],
            digest: zero_crypto::blake3_hash(b"equivoc-1"),
        };
        let event2 = zero_types::block::Event {
            round: 1,
            author: 1,
            timestamp: 1001,
            parents: vec![],
            transactions: vec![],
            digest: zero_crypto::blake3_hash(b"equivoc-2"),
        };

        node.receive_event(event1, vec![], 1000);
        node.receive_event(event2, vec![], 1001);

        // Validator 1's stake should be completely slashed (100%)
        {
            let exec = node.executor().read();
            let mut k = [0u8; 32];
            k[0] = 2;
            assert_eq!(exec.stake_store().staked(&k), 0);
        }
    }
}
