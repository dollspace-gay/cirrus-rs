//! Firehose event sequencer and broadcast.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::error::Result;
use crate::storage::SqliteStorage;

/// Default channel capacity for the firehose broadcast.
const CHANNEL_CAPACITY: usize = 1024;

/// A firehose event that can be broadcast.
#[derive(Debug, Clone)]
pub enum FirehoseEvent {
    /// A commit event.
    Commit(CommitEvent),
}

impl FirehoseEvent {
    /// Encodes the event as a framed message (type header + DAG-CBOR body).
    ///
    /// Uses `ciborium::Value` directly to ensure CID fields use CBOR tag 42
    /// links as required by the AT Protocol firehose format.
    ///
    /// # Errors
    /// Returns an error if encoding fails.
    #[allow(clippy::unwrap_used)]
    pub fn encode(&self) -> Result<Vec<u8>> {
        use ciborium::Value as V;
        use cirrus_common::error::Error;

        match self {
            Self::Commit(event) => {
                // Header: {"op": 1, "t": "#commit"} — keys sorted by encoded length
                let header = V::Map(vec![
                    (V::Text("op".to_string()), V::Integer(1.into())),
                    (V::Text("t".to_string()), V::Text("#commit".to_string())),
                ]);

                // Build body with proper CID links
                let commit_cid = str_to_cid_link(&event.commit);
                let ops: Vec<V> = event.ops.iter().map(|op| {
                    let fields = vec![
                        (V::Text("action".to_string()), V::Text(op.action.clone())),
                        (V::Text("cid".to_string()), match &op.cid {
                            Some(c) => str_to_cid_link(c),
                            None => V::Null,
                        }),
                        (V::Text("path".to_string()), V::Text(op.path.clone())),
                    ];
                    V::Map(fields)
                }).collect();

                let body = V::Map(vec![
                    (V::Text("blocks".to_string()), V::Bytes(event.blocks.clone())),
                    (V::Text("commit".to_string()), commit_cid),
                    (V::Text("ops".to_string()), V::Array(ops)),
                    (V::Text("rebase".to_string()), V::Bool(event.rebase)),
                    (V::Text("repo".to_string()), V::Text(event.repo.clone())),
                    (V::Text("rev".to_string()), V::Text(event.rev.clone())),
                    (V::Text("seq".to_string()), V::Integer(event.seq.into())),
                    (V::Text("since".to_string()), match &event.since {
                        Some(s) => V::Text(s.clone()),
                        None => V::Null,
                    }),
                    (V::Text("time".to_string()), V::Text(event.time.clone())),
                    (V::Text("tooBig".to_string()), V::Bool(event.too_big)),
                ]);

                let mut header_bytes = Vec::new();
                ciborium::into_writer(&header, &mut header_bytes)
                    .map_err(|e| Error::CborEncode(e.to_string()))?;
                let mut body_bytes = Vec::new();
                ciborium::into_writer(&body, &mut body_bytes)
                    .map_err(|e| Error::CborEncode(e.to_string()))?;

                let mut frame = Vec::with_capacity(header_bytes.len() + body_bytes.len());
                frame.extend_from_slice(&header_bytes);
                frame.extend_from_slice(&body_bytes);
                Ok(frame)
            }
        }
    }
}

/// Converts a CID string to a CBOR tag 42 link value.
fn str_to_cid_link(cid_str: &str) -> ciborium::Value {
    use ciborium::Value as V;
    match cirrus_common::cid::Cid::from_string(cid_str) {
        Ok(cid) => {
            let mut bytes = vec![0x00]; // identity multibase prefix
            bytes.extend_from_slice(&cid.to_bytes());
            V::Tag(42, Box::new(V::Bytes(bytes)))
        }
        Err(_) => V::Text(cid_str.to_string()), // fallback to string
    }
}

/// A firehose commit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitEvent {
    /// Sequence number.
    pub seq: i64,
    /// Whether this is a rebase.
    pub rebase: bool,
    /// Whether the commit is too big to include blocks.
    #[serde(rename = "tooBig")]
    pub too_big: bool,
    /// Repository DID.
    pub repo: String,
    /// Commit CID.
    pub commit: String,
    /// Revision after commit.
    pub rev: String,
    /// Previous revision.
    pub since: Option<String>,
    /// CAR file bytes with blocks.
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    /// Operations performed.
    pub ops: Vec<RepoOpEvent>,
    /// Blob CIDs referenced.
    pub blobs: Vec<String>,
    /// Timestamp.
    pub time: String,
}

/// A repository operation in an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoOpEvent {
    /// Operation action.
    pub action: String,
    /// Path (collection/rkey).
    pub path: String,
    /// CID of the record (for create/update).
    pub cid: Option<String>,
}

/// Firehose broadcast channel.
#[derive(Clone)]
pub struct Firehose {
    sender: broadcast::Sender<Arc<FirehoseEvent>>,
}

impl Default for Firehose {
    fn default() -> Self {
        Self::new()
    }
}

impl Firehose {
    /// Creates a new firehose broadcast channel.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Publishes an event to all subscribers.
    pub fn publish(&self, event: FirehoseEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.sender.send(Arc::new(event));
    }

    /// Subscribes to the firehose.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<FirehoseEvent>> {
        self.sender.subscribe()
    }
}

/// Sequencer for firehose events.
pub struct Sequencer<'a> {
    storage: &'a SqliteStorage,
    firehose: &'a Firehose,
}

impl<'a> Sequencer<'a> {
    /// Creates a new sequencer.
    #[must_use]
    pub const fn new(storage: &'a SqliteStorage, firehose: &'a Firehose) -> Self {
        Self { storage, firehose }
    }

    /// Gets the current sequence number.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn current_seq(&self) -> Result<i64> {
        let state = self.storage.get_repo_state()?;
        Ok(state.seq)
    }

    /// Publishes a commit event.
    pub fn publish_commit(&self, event: CommitEvent) {
        self.firehose.publish(FirehoseEvent::Commit(event));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commit_event_serialization() {
        let event = CommitEvent {
            seq: 1,
            rebase: false,
            too_big: false,
            repo: "did:plc:test".to_string(),
            commit: "bafycommit".to_string(),
            rev: "rev1".to_string(),
            since: None,
            blocks: vec![1, 2, 3],
            ops: vec![RepoOpEvent {
                action: "create".to_string(),
                path: "app.bsky.feed.post/abc".to_string(),
                cid: Some("bafyrecord".to_string()),
            }],
            blobs: vec![],
            time: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("did:plc:test"));
    }

    #[test]
    fn test_firehose_creation() {
        let firehose = Firehose::new();
        let _rx = firehose.subscribe();
    }

    #[tokio::test]
    async fn test_firehose_broadcast() {
        let firehose = Firehose::new();
        let mut rx = firehose.subscribe();

        let event = CommitEvent {
            seq: 1,
            rebase: false,
            too_big: false,
            repo: "did:plc:test".to_string(),
            commit: "bafycommit".to_string(),
            rev: "rev1".to_string(),
            since: None,
            blocks: vec![],
            ops: vec![],
            blobs: vec![],
            time: "2024-01-01T00:00:00Z".to_string(),
        };

        firehose.publish(FirehoseEvent::Commit(event));

        let received = rx.recv().await.unwrap();
        if let FirehoseEvent::Commit(c) = &*received {
            assert_eq!(c.seq, 1);
            assert_eq!(c.repo, "did:plc:test");
        } else {
            panic!("wrong event type");
        }
    }

    #[test]
    fn test_firehose_event_encode() {
        let event = CommitEvent {
            seq: 1,
            rebase: false,
            too_big: false,
            repo: "did:plc:test".to_string(),
            commit: "bafycommit".to_string(),
            rev: "rev1".to_string(),
            since: None,
            blocks: vec![],
            ops: vec![],
            blobs: vec![],
            time: "2024-01-01T00:00:00Z".to_string(),
        };

        let fe = FirehoseEvent::Commit(event);
        let encoded = fe.encode().unwrap();
        assert!(!encoded.is_empty());
    }
}
