use std::collections::{BTreeMap, HashMap, HashSet};

use zero_types::{
    Round, ValidatorIndex,
    block::{BlockRef, Event},
};

use crate::committee::Committee;

/// The consensus DAG.
///
/// Stores events organized by round and author. Events reference
/// parent events to form a DAG. When an event is transitively
/// referenced by 2/3+ of validators, it is considered finalized.
///
/// Inspired by Mysticeti's DAG state management and Lachesis's
/// leaderless aBFT approach.
pub struct Dag {
    /// Events indexed by their block reference.
    events: HashMap<BlockRef, Event>,
    /// Events organized by round, then by author.
    rounds: BTreeMap<Round, HashMap<ValidatorIndex, BlockRef>>,
    /// The current round (highest round with an event from this validator).
    current_round: Round,
    /// Events that have been finalized.
    finalized: HashSet<BlockRef>,
    /// The highest round that has been fully finalized.
    last_finalized_round: Round,
}

/// Result of inserting an event into the DAG.
#[derive(Debug, PartialEq)]
pub enum InsertResult {
    /// Event was inserted successfully.
    Inserted,
    /// Duplicate event (same digest) — ignored.
    Duplicate,
    /// Equivocation: validator produced a different event for the same round.
    /// Contains the author index.
    Equivocation(ValidatorIndex),
}

impl Dag {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
            rounds: BTreeMap::new(),
            current_round: 0,
            finalized: HashSet::new(),
            last_finalized_round: 0,
        }
    }

    /// Insert an event into the DAG.
    ///
    /// Returns `InsertResult::Equivocation` if the validator already has a different
    /// event in this round. The equivocating event is rejected (not inserted).
    pub fn insert(&mut self, event: Event) -> InsertResult {
        let block_ref = event.reference();

        // Check for duplicate (exact same event)
        if self.events.contains_key(&block_ref) {
            return InsertResult::Duplicate;
        }

        // Check for equivocation: same author + same round but different digest
        let round_authors = self.rounds.entry(event.round).or_default();
        if let Some(existing_ref) = round_authors.get(&event.author)
            && existing_ref.digest != block_ref.digest
        {
            // Equivocation detected — reject the new event
            return InsertResult::Equivocation(event.author);
        }

        round_authors.insert(event.author, block_ref);

        if event.round > self.current_round {
            self.current_round = event.round;
        }

        self.events.insert(block_ref, event);
        InsertResult::Inserted
    }

    /// Get an event by its block reference.
    pub fn get(&self, block_ref: &BlockRef) -> Option<&Event> {
        self.events.get(block_ref)
    }

    /// Get all events in a given round.
    pub fn events_in_round(&self, round: Round) -> Vec<&Event> {
        self.rounds
            .get(&round)
            .map(|authors| {
                authors
                    .values()
                    .filter_map(|r| self.events.get(r))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if an event has been finalized.
    pub fn is_finalized(&self, block_ref: &BlockRef) -> bool {
        self.finalized.contains(block_ref)
    }

    /// Try to finalize events based on the 2/3+ rule.
    ///
    /// An event at round R is finalized if events from 2/3+ of validators
    /// at round R+1 (or later) transitively reference it.
    ///
    /// Returns newly finalized events in causal order.
    pub fn try_finalize(&mut self, committee: &Committee) -> Vec<BlockRef> {
        let mut newly_finalized = Vec::new();

        // Check rounds that haven't been finalized yet
        let rounds_to_check: Vec<Round> = self
            .rounds
            .range(self.last_finalized_round..)
            .map(|(&r, _)| r)
            .collect();

        for round in rounds_to_check {
            if let Some(authors) = self.rounds.get(&round) {
                for block_ref in authors.values() {
                    if self.finalized.contains(block_ref) {
                        continue;
                    }

                    // Count stake of validators that have built on this event
                    let supporting_stake = self.supporting_stake(block_ref, committee);
                    if supporting_stake >= committee.quorum_threshold() {
                        self.finalized.insert(*block_ref);
                        newly_finalized.push(*block_ref);
                    }
                }
            }
        }

        // Update last finalized round
        if let Some(max_finalized) = newly_finalized.iter().map(|r| r.round).max()
            && max_finalized > self.last_finalized_round
        {
            self.last_finalized_round = max_finalized;
        }

        // Prune old rounds that are fully finalized
        self.prune_old_rounds();

        newly_finalized
    }

    /// Calculate the total stake of validators whose events (in later rounds)
    /// transitively reference the given event.
    fn supporting_stake(&self, target: &BlockRef, committee: &Committee) -> u64 {
        let mut seen_validators = HashSet::new();
        // Find all events in later rounds
        for (_round, authors) in self.rounds.range((target.round + 1)..) {
            for (&author, block_ref) in authors {
                if self.references_transitively(block_ref, target, 3) {
                    seen_validators.insert(author);
                }
            }
        }

        seen_validators
            .iter()
            .filter_map(|&idx| committee.validator(idx))
            .map(|v| v.stake)
            .sum()
    }

    /// Check if `from` transitively references `target` within `max_depth` hops.
    fn references_transitively(&self, from: &BlockRef, target: &BlockRef, max_depth: u32) -> bool {
        if max_depth == 0 {
            return false;
        }
        if let Some(event) = self.events.get(from) {
            for parent in &event.parents {
                if parent == target {
                    return true;
                }
                if parent.round >= target.round
                    && self.references_transitively(parent, target, max_depth - 1)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Prune rounds that are well below the finalization frontier.
    /// Keep at least 10 rounds of history for catch-up.
    fn prune_old_rounds(&mut self) {
        if self.last_finalized_round < 10 {
            return;
        }
        let cutoff = self.last_finalized_round - 10;
        let old_rounds: Vec<Round> = self.rounds.range(..cutoff).map(|(&r, _)| r).collect();

        for round in old_rounds {
            if let Some(authors) = self.rounds.remove(&round) {
                for block_ref in authors.values() {
                    self.events.remove(block_ref);
                    self.finalized.remove(block_ref);
                }
            }
        }
    }

    pub fn current_round(&self) -> Round {
        self.current_round
    }

    pub fn last_finalized_round(&self) -> Round {
        self.last_finalized_round
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

impl Default for Dag {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::ValidatorInfo;

    fn test_committee_3() -> Committee {
        Committee::new(vec![
            ValidatorInfo {
                index: 0,
                public_key: [1u8; 32],
                stake: 100,
            },
            ValidatorInfo {
                index: 1,
                public_key: [2u8; 32],
                stake: 100,
            },
            ValidatorInfo {
                index: 2,
                public_key: [3u8; 32],
                stake: 100,
            },
        ])
    }

    fn make_event(round: Round, author: ValidatorIndex, parents: Vec<BlockRef>) -> Event {
        let digest = zero_crypto::blake3_hash(
            &[&round.to_le_bytes()[..], &(author as u16).to_le_bytes()[..]].concat(),
        );
        Event {
            round,
            author,
            timestamp: 0,
            parents,
            transactions: vec![],
            digest,
        }
    }

    /// Create an event with a unique salt to produce a different digest for the same round/author.
    fn make_event_with_salt(round: Round, author: ValidatorIndex, salt: u8) -> Event {
        let digest = zero_crypto::blake3_hash(
            &[
                &round.to_le_bytes()[..],
                &(author as u16).to_le_bytes()[..],
                &[salt],
            ]
            .concat(),
        );
        Event {
            round,
            author,
            timestamp: 0,
            parents: vec![],
            transactions: vec![],
            digest,
        }
    }

    #[test]
    fn insert_and_retrieve() {
        let mut dag = Dag::new();
        let e = make_event(1, 0, vec![]);
        let block_ref = e.reference();
        dag.insert(e);

        assert!(dag.get(&block_ref).is_some());
        assert_eq!(dag.current_round(), 1);
        assert_eq!(dag.event_count(), 1);
    }

    #[test]
    fn finalization_requires_quorum() {
        let committee = test_committee_3();
        let mut dag = Dag::new();

        // Round 1: all three validators produce events
        let e0 = make_event(1, 0, vec![]);
        let e1 = make_event(1, 1, vec![]);
        let e2 = make_event(1, 2, vec![]);
        let r0 = e0.reference();
        let r1 = e1.reference();
        let r2 = e2.reference();
        dag.insert(e0);
        dag.insert(e1);
        dag.insert(e2);

        // Round 2: all three validators reference all round-1 events
        let e0_2 = make_event(2, 0, vec![r0, r1, r2]);
        let e1_2 = make_event(2, 1, vec![r0, r1, r2]);
        let e2_2 = make_event(2, 2, vec![r0, r1, r2]);
        dag.insert(e0_2);
        dag.insert(e1_2);
        dag.insert(e2_2);

        // All round-1 events should now be finalized
        let finalized = dag.try_finalize(&committee);
        assert_eq!(finalized.len(), 3);
        assert!(dag.is_finalized(&r0));
        assert!(dag.is_finalized(&r1));
        assert!(dag.is_finalized(&r2));
    }

    #[test]
    fn equivocation_detected() {
        let mut dag = Dag::new();

        // Validator 0 produces an event in round 1
        let e1 = make_event_with_salt(1, 0, 0);
        assert_eq!(dag.insert(e1), InsertResult::Inserted);

        // Validator 0 tries to produce a DIFFERENT event in round 1 (equivocation)
        let e2 = make_event_with_salt(1, 0, 1);
        assert_eq!(dag.insert(e2), InsertResult::Equivocation(0));

        // DAG should still have only the first event
        assert_eq!(dag.event_count(), 1);
    }

    #[test]
    fn duplicate_is_harmless() {
        let mut dag = Dag::new();

        let e = make_event(1, 0, vec![]);
        assert_eq!(dag.insert(e.clone()), InsertResult::Inserted);
        assert_eq!(dag.insert(e), InsertResult::Duplicate);
        assert_eq!(dag.event_count(), 1);
    }

    #[test]
    fn different_validators_same_round_ok() {
        let mut dag = Dag::new();

        let e0 = make_event(1, 0, vec![]);
        let e1 = make_event(1, 1, vec![]);
        let e2 = make_event(1, 2, vec![]);

        assert_eq!(dag.insert(e0), InsertResult::Inserted);
        assert_eq!(dag.insert(e1), InsertResult::Inserted);
        assert_eq!(dag.insert(e2), InsertResult::Inserted);
        assert_eq!(dag.event_count(), 3);
    }
}
