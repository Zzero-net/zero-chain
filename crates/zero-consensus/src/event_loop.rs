use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use tokio::time::{Duration, interval};
use tracing::{debug, info};

use zero_types::{Transfer, block::Event};

use crate::Node;

/// Trait for broadcasting events to peers.
/// Defined here so the event loop doesn't depend on the network crate.
pub trait Broadcaster: Send + Sync + 'static {
    /// Broadcast an event + its transfers to peers. Returns (success_count, total_peers).
    fn broadcast(
        &self,
        event: &Event,
        transfers: &[Transfer],
    ) -> impl std::future::Future<Output = (usize, usize)> + Send;
    /// Pull events from peers for catch-up. Tries all peers, returns merged results.
    fn pull_catchup(
        &self,
        from_round: u32,
        max_events: u32,
    ) -> impl std::future::Future<Output = Vec<(Event, Vec<Transfer>)>> + Send;
    /// Number of known peers.
    fn peer_count(&self) -> usize;
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Run the consensus event loop.
///
/// This is the main driver that:
///   1. Periodically produces events from pending transfers
///   2. Broadcasts events to peers via gossip
///   3. Runs finalization and executes finalized transfers
///   4. Performs periodic maintenance (rate limiter cleanup, batch pruning)
///
/// Runs until the shutdown signal is received.
pub async fn run_event_loop<B: Broadcaster>(
    node: Arc<RwLock<Node>>,
    broadcaster: Arc<B>,
    event_interval_ms: u64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = interval(Duration::from_millis(event_interval_ms));
    let heartbeat_ms = std::cmp::max(event_interval_ms * 5, 1000); // heartbeat every 5 ticks or 1s
    let mut heartbeat_tick = interval(Duration::from_millis(heartbeat_ms));
    let mut maintenance_tick = interval(Duration::from_secs(10));
    let mut snapshot_tick = interval(Duration::from_secs(60));
    let mut catchup_tick = interval(Duration::from_secs(10));

    info!(
        interval_ms = event_interval_ms,
        peers = broadcaster.peer_count(),
        "Consensus event loop started"
    );

    loop {
        tokio::select! {
            _ = tick.tick() => {
                let ts = now_ms();

                // 1. Try to produce an event from pending transfers
                let event_and_batch = {
                    let mut n = node.write();
                    if let Some(event) = n.try_produce_event(ts) {
                        // Get the batch for gossip (clone before it might be taken by finalization)
                        let batch = n.validator().has_batch(&event.digest);
                        if batch {
                            // We need to peek at the batch without taking it
                            // For gossip we'll re-read from the validator
                            Some(event)
                        } else {
                            Some(event)
                        }
                    } else {
                        None
                    }
                };

                // 2. Broadcast to peers
                if let Some(event) = event_and_batch {
                    // Get the transfer batch for this event
                    let batch = {
                        let n = node.read();
                        // We need the batch from the validator, but we can't take it
                        // (finalization needs it). Clone from the validator's batch store.
                        n.validator().peek_batch(&event.digest)
                    };

                    if let Some(transfers) = batch {
                        let (ok, total) = broadcaster.broadcast(&event, &transfers).await;
                        if total > 0 {
                            debug!(
                                round = event.round,
                                ok,
                                total,
                                "Broadcast event to peers"
                            );
                        }
                    }
                }

                // 3. Try finalization
                let executed = {
                    let mut n = node.write();
                    n.try_finalize_and_execute(ts)
                };

                if executed > 0 {
                    debug!(executed, "Finalized transfers");
                }
            }

            _ = heartbeat_tick.tick() => {
                let ts = now_ms();

                // Produce a heartbeat if no event was produced recently.
                // This keeps the DAG moving so finalization can proceed.
                let event = {
                    let mut n = node.write();
                    n.produce_heartbeat(ts)
                };

                // Broadcast heartbeat to peers
                let batch = {
                    let n = node.read();
                    n.validator().peek_batch(&event.digest)
                };
                let transfers = batch.unwrap_or_default();
                let (ok, total) = broadcaster.broadcast(&event, &transfers).await;
                if total > 0 {
                    debug!(
                        round = event.round,
                        ok,
                        total,
                        "Broadcast heartbeat to peers"
                    );
                }

                // Try finalization after heartbeat
                let executed = {
                    let mut n = node.write();
                    n.try_finalize_and_execute(ts)
                };
                if executed > 0 {
                    debug!(executed, "Finalized transfers (heartbeat)");
                }
            }

            _ = maintenance_tick.tick() => {
                let ts = now_ms();
                node.write().maintenance(ts);
            }

            _ = snapshot_tick.tick() => {
                // Snapshot is handled externally — just log stats
                let n = node.read();
                let exec = n.executor().read();
                info!(
                    accounts = exec.accounts().len(),
                    transfers = exec.transfer_log().total_written(),
                    finalized = n.finalized_tx_count(),
                    fee_pool = exec.fee_pool(),
                    "Node status"
                );
            }

            _ = catchup_tick.tick() => {
                // Pull-based catch-up: fill DAG gaps by requesting events from peers
                let current_round = node.read().dag().read().current_round();
                let from_round = current_round.saturating_sub(20);

                let events = broadcaster.pull_catchup(from_round, 200).await;
                if !events.is_empty() {
                    let mut accepted = 0u32;
                    let total = events.len();
                    {
                        let ts = now_ms();
                        let mut n = node.write();
                        for (event, transfers) in events {
                            if n.receive_event(event, transfers, ts) {
                                accepted += 1;
                            }
                        }
                    }
                    if accepted > 0 {
                        info!(accepted, total, from_round, "Pull catch-up: new events ingested");
                        // Try finalization after catch-up
                        let ts = now_ms();
                        let executed = node.write().try_finalize_and_execute(ts);
                        if executed > 0 {
                            debug!(executed, "Finalized transfers (catch-up)");
                        }
                    }
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("Consensus event loop shutting down");
                    break;
                }
            }
        }
    }
}
