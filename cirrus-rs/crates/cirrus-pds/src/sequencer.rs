//! Firehose event sequencer.

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::storage::SqliteStorage;

/// A firehose commit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitEvent {
    /// Sequence number.
    pub seq: i64,
    /// Whether this is a rebase.
    pub rebase: bool,
    /// Whether the commit is too big to include blocks.
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

/// Sequencer for firehose events.
pub struct Sequencer<'a> {
    storage: &'a SqliteStorage,
}

impl<'a> Sequencer<'a> {
    /// Creates a new sequencer.
    #[must_use]
    pub const fn new(storage: &'a SqliteStorage) -> Self {
        Self { storage }
    }

    /// Gets the current sequence number.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn current_seq(&self) -> Result<i64> {
        let state = self.storage.get_repo_state()?;
        Ok(state.seq)
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
}
