use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use zero_types::{
    block::{BlockRef, Event},
    Hash, Round, TimestampMs, Transfer, ValidatorIndex,
};

use crate::{Committee, Dag};

/// Per-validator consensus state.
///
/// Each validator maintains its own view of the DAG,
/// produces events containing batched transfers,
/// and participates in finalization.
pub struct ValidatorState {
    /// This validator's index.
    pub index: ValidatorIndex,
    /// The consensus DAG (shared, behind RwLock).
    dag: Arc<RwLock<Dag>>,
    /// The current committee.
    committee: Arc<Committee>,
    /// Pending transfers waiting to be included in the next event.
    pending: Vec<Transfer>,
    /// Maximum transfers per event.
    max_batch_size: usize,
    /// This validator's last produced round.
    last_round: Round,
    /// Transfer batches keyed by event digest, for retrieval on finalization.
    batches: HashMap<Hash, Vec<Transfer>>,
}

impl ValidatorState {
    pub fn new(
        index: ValidatorIndex,
        dag: Arc<RwLock<Dag>>,
        committee: Arc<Committee>,
        max_batch_size: usize,
    ) -> Self {
        Self {
            index,
            dag,
            committee,
            pending: Vec::new(),
            max_batch_size,
            last_round: 0,
            batches: HashMap::new(),
        }
    }

    /// Add a transfer to the pending pool.
    pub fn submit_transfer(&mut self, transfer: Transfer) {
        self.pending.push(transfer);
    }

    /// Number of pending transfers.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Produce a new event, either with pending transfers or as a heartbeat.
    ///
    /// The event references:
    /// - Our own last event (self-parent)
    /// - The latest events from other validators (other-parents)
    ///
    /// If `heartbeat` is true, produces an event even with no pending transfers
    /// (needed for DAG progress / quorum formation).
    pub fn try_produce_event(&mut self, timestamp: TimestampMs) -> Option<Event> {
        self.produce_event_inner(timestamp, false)
    }

    /// Produce a heartbeat event (empty batch) to advance the DAG.
    pub fn produce_heartbeat(&mut self, timestamp: TimestampMs) -> Event {
        self.produce_event_inner(timestamp, true)
            .expect("heartbeat always produces")
    }

    fn produce_event_inner(&mut self, timestamp: TimestampMs, heartbeat: bool) -> Option<Event> {
        if self.pending.is_empty() && !heartbeat {
            return None;
        }

        let batch_size = std::cmp::min(self.pending.len(), self.max_batch_size);
        let batch: Vec<Transfer> = self.pending.drain(..batch_size).collect();

        let dag = self.dag.read();

        // Determine parents: latest event from each validator
        let round = dag.current_round() + 1;
        let parents = self.collect_parents(&dag, round);

        // Transaction indices are just sequence numbers within this batch
        let transactions: Vec<u32> = (0..batch.len() as u32).collect();

        // Compute digest
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&round.to_le_bytes());
        hasher_input.extend_from_slice(&self.index.to_le_bytes());
        hasher_input.extend_from_slice(&timestamp.to_le_bytes());
        for p in &parents {
            hasher_input.extend_from_slice(&p.digest);
        }
        for tx in &batch {
            hasher_input.extend_from_slice(&tx.to_storage_bytes());
        }
        let digest = zero_crypto::blake3_hash(&hasher_input);

        drop(dag);

        let event = Event {
            round,
            author: self.index,
            timestamp,
            parents,
            transactions,
            digest,
        };

        // Store the batch for later retrieval on finalization
        self.batches.insert(digest, batch);

        // Insert into DAG (own events should never equivocate)
        let _ = self.dag.write().insert(event.clone());
        self.last_round = round;

        Some(event)
    }

    /// Collect parent references for a new event.
    fn collect_parents(&self, dag: &Dag, new_round: Round) -> Vec<BlockRef> {
        let mut parents = Vec::new();

        if new_round == 0 {
            return parents;
        }

        for round in (0..new_round).rev().take(5) {
            for event in dag.events_in_round(round) {
                let has_author = parents.iter().any(|p: &BlockRef| p.author == event.author);
                if !has_author {
                    parents.push(event.reference());
                }
            }
            if parents.len() >= self.committee.size() {
                break;
            }
        }

        parents
    }

    /// Retrieve the transfer batch for a finalized event.
    /// Returns None if this validator didn't produce the event or it was already taken.
    pub fn take_batch(&mut self, digest: &Hash) -> Option<Vec<Transfer>> {
        self.batches.remove(digest)
    }

    /// Check if we have a batch for the given digest.
    pub fn has_batch(&self, digest: &Hash) -> bool {
        self.batches.contains_key(digest)
    }

    /// Get a clone of a batch without removing it (for gossip broadcast).
    pub fn peek_batch(&self, digest: &Hash) -> Option<Vec<Transfer>> {
        self.batches.get(digest).cloned()
    }

    /// Try to finalize events in the DAG.
    /// Returns block refs of newly finalized events.
    pub fn try_finalize(&self) -> Vec<BlockRef> {
        self.dag.write().try_finalize(&self.committee)
    }

    /// Update the committee reference (for epoch rotation).
    pub fn set_committee(&mut self, committee: Arc<Committee>) {
        self.committee = committee;
    }

    pub fn last_round(&self) -> Round {
        self.last_round
    }

    /// Number of stored batches (for diagnostics).
    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    /// Clean up old batches that will never be finalized.
    /// Call periodically to prevent unbounded growth.
    pub fn prune_batches(&mut self, keep_last: usize) {
        if self.batches.len() > keep_last * 2 {
            // Keep only the most recent batches; old ones won't finalize
            // Since we can't order by time easily, just clear if too many
            // In practice finalized batches are removed via take_batch
            let excess = self.batches.len() - keep_last;
            let keys: Vec<Hash> = self.batches.keys().take(excess).copied().collect();
            for k in keys {
                self.batches.remove(&k);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::ValidatorInfo;

    #[test]
    fn submit_and_produce() {
        let committee = Arc::new(Committee::new(vec![ValidatorInfo {
            index: 0,
            public_key: [1u8; 32],
            stake: 100,
        }]));
        let dag = Arc::new(RwLock::new(Dag::new()));
        let mut vs = ValidatorState::new(0, dag, committee, 100);

        let tx = Transfer {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 50,
            nonce: 1,
            signature: [0u8; 64],
        };

        vs.submit_transfer(tx);
        assert_eq!(vs.pending_count(), 1);

        let event = vs.try_produce_event(1000).unwrap();
        assert_eq!(event.round, 1);
        assert_eq!(event.author, 0);
        assert_eq!(event.transactions.len(), 1);
        assert_eq!(vs.pending_count(), 0);

        // Batch should be stored
        assert!(vs.has_batch(&event.digest));
        let batch = vs.take_batch(&event.digest).unwrap();
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn no_event_without_transfers() {
        let committee = Arc::new(Committee::new(vec![ValidatorInfo {
            index: 0,
            public_key: [1u8; 32],
            stake: 100,
        }]));
        let dag = Arc::new(RwLock::new(Dag::new()));
        let mut vs = ValidatorState::new(0, dag, committee, 100);

        assert!(vs.try_produce_event(1000).is_none());
    }
}
