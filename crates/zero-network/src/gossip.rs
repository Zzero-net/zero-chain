use std::sync::Arc;

use tonic::{
    Request, Response, Status,
    transport::{Certificate, Channel, ClientTlsConfig, Identity},
};
use tracing::{debug, info, warn};

use zero_consensus::node::GossipHandler;
use zero_types::{
    Transfer,
    block::{BlockRef, Event},
};

use crate::proto::{
    GossipAck, GossipBlockRef, GossipEvent, GossipTransfer, PullRequest, PullResponse,
    zero_gossip_server::ZeroGossip,
};

/// gRPC gossip server implementation.
pub struct GossipServer<H: GossipHandler> {
    handler: Arc<H>,
}

impl<H: GossipHandler> GossipServer<H> {
    pub fn new(handler: Arc<H>) -> Self {
        Self { handler }
    }
}

#[tonic::async_trait]
impl<H: GossipHandler> ZeroGossip for GossipServer<H> {
    async fn push_event(
        &self,
        request: Request<GossipEvent>,
    ) -> Result<Response<GossipAck>, Status> {
        let msg = request.into_inner();

        let (event, transfers) = match decode_gossip_event(msg) {
            Ok(v) => v,
            Err(e) => {
                return Ok(Response::new(GossipAck {
                    accepted: false,
                    reason: e,
                }));
            }
        };

        let round = event.round;
        let author = event.author;
        let txs = transfers.len();

        match self.handler.handle_event(event, transfers) {
            Ok(accepted) => {
                info!(round, author, txs, accepted, "Gossip event received");
                Ok(Response::new(GossipAck {
                    accepted,
                    reason: String::new(),
                }))
            }
            Err(e) => {
                warn!(err = %e, "Gossip event rejected");
                Ok(Response::new(GossipAck {
                    accepted: false,
                    reason: e,
                }))
            }
        }
    }

    async fn pull_events(
        &self,
        request: Request<PullRequest>,
    ) -> Result<Response<PullResponse>, Status> {
        let req = request.into_inner();
        let events = self.handler.get_events_from(req.from_round, req.max_events);

        let gossip_events: Vec<GossipEvent> = events
            .into_iter()
            .map(|(event, transfers)| encode_gossip_event(&event, &transfers))
            .collect();

        Ok(Response::new(PullResponse {
            events: gossip_events,
        }))
    }
}

/// TLS configuration for gossip connections.
#[derive(Clone)]
pub struct GossipTlsConfig {
    pub client_identity: Identity,
    pub ca_certificate: Certificate,
}

/// Gossip client for pushing events to peers.
pub struct GossipClient {
    peers: Vec<String>,
    tls: Option<GossipTlsConfig>,
}

impl GossipClient {
    pub fn new(peers: Vec<String>) -> Self {
        Self { peers, tls: None }
    }

    pub fn with_tls(peers: Vec<String>, tls: GossipTlsConfig) -> Self {
        Self {
            peers,
            tls: Some(tls),
        }
    }

    /// Broadcast an event to all peers. Returns (success_count, total_peers).
    pub async fn broadcast(&self, event: &Event, transfers: &[Transfer]) -> (usize, usize) {
        let msg = encode_gossip_event(event, transfers);
        let mut successes = 0;

        for peer in &self.peers {
            match self.push_to_peer(peer, msg.clone()).await {
                Ok(ack) => {
                    if ack.accepted {
                        successes += 1;
                    } else {
                        debug!(peer, reason = ack.reason, "Peer rejected event");
                    }
                }
                Err(e) => {
                    warn!(peer, err = %e, "Failed to push event to peer");
                }
            }
        }

        (successes, self.peers.len())
    }

    /// Pull events from a specific peer for catch-up.
    pub async fn pull_from_peer(
        &self,
        peer: &str,
        from_round: u32,
        max_events: u32,
    ) -> Result<Vec<(Event, Vec<Transfer>)>, tonic::Status> {
        let channel = self.connect(peer).await?;
        let mut client = crate::proto::zero_gossip_client::ZeroGossipClient::new(channel);

        let resp = client
            .pull_events(PullRequest {
                from_round,
                max_events,
            })
            .await?
            .into_inner();

        let mut results = Vec::new();
        for ge in resp.events {
            match decode_gossip_event(ge) {
                Ok((event, transfers)) => results.push((event, transfers)),
                Err(e) => warn!(err = e, "Skipping invalid event from peer"),
            }
        }

        Ok(results)
    }

    async fn push_to_peer(&self, peer: &str, msg: GossipEvent) -> Result<GossipAck, tonic::Status> {
        let channel = self.connect(peer).await?;
        let mut client = crate::proto::zero_gossip_client::ZeroGossipClient::new(channel);

        let resp = client.push_event(msg).await?;
        Ok(resp.into_inner())
    }

    /// Connect to a peer, with mTLS if configured.
    async fn connect(&self, peer: &str) -> Result<Channel, tonic::Status> {
        let endpoint = Channel::from_shared(peer.to_string())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let endpoint = if let Some(tls) = &self.tls {
            let tls_config = ClientTlsConfig::new()
                .domain_name("node.zero.network")
                .ca_certificate(tls.ca_certificate.clone())
                .identity(tls.client_identity.clone());
            endpoint
                .tls_config(tls_config)
                .map_err(|e| Status::internal(format!("TLS config error: {}", e)))?
        } else {
            endpoint
        };

        endpoint
            .connect()
            .await
            .map_err(|e| Status::unavailable(e.to_string()))
    }

    /// Pull events from all peers for catch-up. Merges results, deduplicates by digest.
    pub async fn pull_catchup(
        &self,
        from_round: u32,
        max_events: u32,
    ) -> Vec<(Event, Vec<Transfer>)> {
        let mut seen = std::collections::HashSet::new();
        let mut all_events = Vec::new();

        for peer in &self.peers {
            match self.pull_from_peer(peer, from_round, max_events).await {
                Ok(events) => {
                    for (event, transfers) in events {
                        if seen.insert(event.digest) {
                            all_events.push((event, transfers));
                        }
                    }
                }
                Err(e) => {
                    debug!(peer, err = %e, "Pull catch-up failed from peer");
                }
            }
        }

        all_events
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}

// --- Encoding/decoding helpers ---

pub fn encode_gossip_event(event: &Event, transfers: &[Transfer]) -> GossipEvent {
    GossipEvent {
        round: event.round,
        author: event.author as u32,
        timestamp: event.timestamp,
        parents: event
            .parents
            .iter()
            .map(|p| GossipBlockRef {
                round: p.round,
                author: p.author as u32,
                digest: p.digest.to_vec(),
            })
            .collect(),
        transfers: transfers
            .iter()
            .map(|tx| GossipTransfer {
                from: tx.from.to_vec(),
                to: tx.to.to_vec(),
                amount: tx.amount,
                nonce: tx.nonce,
                signature: tx.signature.to_vec(),
            })
            .collect(),
        digest: event.digest.to_vec(),
    }
}

pub fn decode_gossip_event(msg: GossipEvent) -> Result<(Event, Vec<Transfer>), String> {
    let digest: [u8; 32] = msg
        .digest
        .try_into()
        .map_err(|_| "digest must be 32 bytes".to_string())?;

    let mut parents = Vec::new();
    for p in msg.parents {
        let d: [u8; 32] = p
            .digest
            .try_into()
            .map_err(|_| "parent digest must be 32 bytes".to_string())?;
        parents.push(BlockRef {
            round: p.round,
            author: p.author as u16,
            digest: d,
        });
    }

    let mut transfers = Vec::new();
    for t in msg.transfers {
        let from: [u8; 32] = t
            .from
            .try_into()
            .map_err(|_| "from must be 32 bytes".to_string())?;
        let to: [u8; 32] =
            t.to.try_into()
                .map_err(|_| "to must be 32 bytes".to_string())?;
        let sig: [u8; 64] = t
            .signature
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        transfers.push(Transfer {
            from,
            to,
            amount: t.amount,
            nonce: t.nonce,
            signature: sig,
        });
    }

    let event = Event {
        round: msg.round,
        author: msg.author as u16,
        timestamp: msg.timestamp,
        parents,
        transactions: (0..transfers.len() as u32).collect(),
        digest,
    };

    Ok((event, transfers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event() -> Event {
        Event {
            round: 5,
            author: 1,
            timestamp: 1234567890,
            parents: vec![
                BlockRef {
                    round: 4,
                    author: 0,
                    digest: [0xAA; 32],
                },
                BlockRef {
                    round: 4,
                    author: 2,
                    digest: [0xBB; 32],
                },
            ],
            transactions: vec![0, 1],
            digest: [0xCC; 32],
        }
    }

    fn test_transfers() -> Vec<Transfer> {
        vec![
            Transfer {
                from: [0x01; 32],
                to: [0x02; 32],
                amount: 1000,
                nonce: 1,
                signature: [0x11; 64],
            },
            Transfer {
                from: [0x03; 32],
                to: [0x04; 32],
                amount: 500,
                nonce: 2,
                signature: [0x22; 64],
            },
        ]
    }

    #[test]
    fn encode_decode_roundtrip() {
        let event = test_event();
        let transfers = test_transfers();

        let msg = encode_gossip_event(&event, &transfers);
        let (decoded_event, decoded_transfers) = decode_gossip_event(msg).unwrap();

        assert_eq!(decoded_event.round, event.round);
        assert_eq!(decoded_event.author, event.author);
        assert_eq!(decoded_event.timestamp, event.timestamp);
        assert_eq!(decoded_event.digest, event.digest);
        assert_eq!(decoded_event.parents.len(), 2);
        assert_eq!(decoded_event.parents[0].round, 4);
        assert_eq!(decoded_event.parents[0].author, 0);
        assert_eq!(decoded_event.parents[0].digest, [0xAA; 32]);
        assert_eq!(decoded_event.parents[1].digest, [0xBB; 32]);
        assert_eq!(decoded_transfers.len(), 2);
        assert_eq!(decoded_transfers[0].from, [0x01; 32]);
        assert_eq!(decoded_transfers[0].to, [0x02; 32]);
        assert_eq!(decoded_transfers[0].amount, 1000);
        assert_eq!(decoded_transfers[0].nonce, 1);
        assert_eq!(decoded_transfers[0].signature, [0x11; 64]);
        assert_eq!(decoded_transfers[1].amount, 500);
    }

    #[test]
    fn encode_decode_empty_event() {
        let event = Event {
            round: 0,
            author: 0,
            timestamp: 0,
            parents: vec![],
            transactions: vec![],
            digest: [0; 32],
        };

        let msg = encode_gossip_event(&event, &[]);
        let (decoded, transfers) = decode_gossip_event(msg).unwrap();

        assert_eq!(decoded.round, 0);
        assert_eq!(decoded.parents.len(), 0);
        assert!(transfers.is_empty());
    }

    #[test]
    fn decode_invalid_digest_length() {
        let msg = GossipEvent {
            round: 1,
            author: 0,
            timestamp: 100,
            parents: vec![],
            transfers: vec![],
            digest: vec![0xAA; 16], // Wrong length
        };
        let result = decode_gossip_event(msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("digest must be 32 bytes"));
    }

    #[test]
    fn decode_invalid_parent_digest() {
        let msg = GossipEvent {
            round: 1,
            author: 0,
            timestamp: 100,
            parents: vec![GossipBlockRef {
                round: 0,
                author: 0,
                digest: vec![0xAA; 10], // Wrong length
            }],
            transfers: vec![],
            digest: vec![0; 32],
        };
        let result = decode_gossip_event(msg);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("parent digest must be 32 bytes")
        );
    }

    #[test]
    fn decode_invalid_transfer_from() {
        let msg = GossipEvent {
            round: 1,
            author: 0,
            timestamp: 100,
            parents: vec![],
            transfers: vec![GossipTransfer {
                from: vec![0x01; 16], // Wrong length
                to: vec![0x02; 32],
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 64],
            }],
            digest: vec![0; 32],
        };
        let result = decode_gossip_event(msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("from must be 32 bytes"));
    }

    #[test]
    fn decode_invalid_transfer_to() {
        let msg = GossipEvent {
            round: 1,
            author: 0,
            timestamp: 100,
            parents: vec![],
            transfers: vec![GossipTransfer {
                from: vec![0x01; 32],
                to: vec![0x02; 10], // Wrong length
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 64],
            }],
            digest: vec![0; 32],
        };
        let result = decode_gossip_event(msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("to must be 32 bytes"));
    }

    #[test]
    fn decode_invalid_transfer_signature() {
        let msg = GossipEvent {
            round: 1,
            author: 0,
            timestamp: 100,
            parents: vec![],
            transfers: vec![GossipTransfer {
                from: vec![0x01; 32],
                to: vec![0x02; 32],
                amount: 100,
                nonce: 1,
                signature: vec![0x03; 32], // Wrong length
            }],
            digest: vec![0; 32],
        };
        let result = decode_gossip_event(msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signature must be 64 bytes"));
    }

    #[test]
    fn encode_preserves_author_u16_range() {
        let event = Event {
            round: 1,
            author: 65535, // max u16
            timestamp: 100,
            parents: vec![BlockRef {
                round: 0,
                author: 12345,
                digest: [0; 32],
            }],
            transactions: vec![],
            digest: [0; 32],
        };

        let msg = encode_gossip_event(&event, &[]);
        assert_eq!(msg.author, 65535);
        assert_eq!(msg.parents[0].author, 12345);

        let (decoded, _) = decode_gossip_event(msg).unwrap();
        assert_eq!(decoded.author, 65535);
        assert_eq!(decoded.parents[0].author, 12345);
    }

    #[test]
    fn transactions_field_populated_from_transfer_count() {
        let event = test_event();
        let transfers = test_transfers();
        let msg = encode_gossip_event(&event, &transfers);
        let (decoded, decoded_transfers) = decode_gossip_event(msg).unwrap();
        // decode_gossip_event creates transaction indices 0..n
        assert_eq!(decoded.transactions, vec![0, 1]);
        assert_eq!(decoded_transfers.len(), 2);
    }

    #[test]
    fn gossip_client_new_peer_count() {
        let client = GossipClient::new(vec![
            "http://10.0.0.1:50051".into(),
            "http://10.0.0.2:50051".into(),
        ]);
        assert_eq!(client.peer_count(), 2);
    }

    #[test]
    fn gossip_client_empty_peers() {
        let client = GossipClient::new(vec![]);
        assert_eq!(client.peer_count(), 0);
    }
}
