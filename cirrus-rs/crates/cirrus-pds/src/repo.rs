//! Repository operations for AT Protocol.

use crate::error::Result;

/// A repository operation.
#[derive(Debug, Clone)]
pub enum RepoOp {
    /// Create a new record.
    Create {
        /// Collection name.
        collection: String,
        /// Record key.
        rkey: String,
        /// Record value as CBOR bytes.
        value: Vec<u8>,
    },
    /// Update an existing record.
    Update {
        /// Collection name.
        collection: String,
        /// Record key.
        rkey: String,
        /// New record value as CBOR bytes.
        value: Vec<u8>,
    },
    /// Delete a record.
    Delete {
        /// Collection name.
        collection: String,
        /// Record key.
        rkey: String,
    },
}

/// A record in the repository.
#[derive(Debug, Clone)]
pub struct Record {
    /// AT URI of the record.
    pub uri: String,
    /// CID of the record.
    pub cid: String,
    /// Record value (JSON).
    pub value: serde_json::Value,
}

/// Repository commit result.
#[derive(Debug, Clone)]
pub struct CommitResult {
    /// New root CID.
    pub root_cid: String,
    /// New revision.
    pub rev: String,
    /// Sequence number.
    pub seq: i64,
}

/// Generates a new record key (TID).
#[must_use]
pub fn generate_rkey() -> String {
    cirrus_common::Tid::now().to_string()
}

/// Builds an AT URI from components.
#[must_use]
pub fn make_at_uri(did: &str, collection: &str, rkey: &str) -> String {
    format!("at://{did}/{collection}/{rkey}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_rkey() {
        let rkey1 = generate_rkey();
        let rkey2 = generate_rkey();

        assert_eq!(rkey1.len(), 13);
        assert_ne!(rkey1, rkey2);
    }

    #[test]
    fn test_make_at_uri() {
        let uri = make_at_uri("did:plc:user", "app.bsky.feed.post", "abc123");
        assert_eq!(uri, "at://did:plc:user/app.bsky.feed.post/abc123");
    }
}
