//! Repository operations for AT Protocol.

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

/// Maximum allowed record key length per AT Protocol spec.
const MAX_RKEY_LEN: usize = 512;

/// Maximum allowed collection NSID length.
const MAX_COLLECTION_LEN: usize = 317;

/// Maximum allowed record payload size in bytes (64 KB for JSON records).
pub const MAX_RECORD_SIZE: usize = 65_536;

/// Validates a record key per AT Protocol spec.
///
/// Valid rkeys contain only `[a-zA-Z0-9._:~-]`, are at most 512 chars,
/// and cannot be `.` or `..`.
pub fn validate_rkey(rkey: &str) -> crate::error::Result<()> {
    if rkey.is_empty() {
        return Err(crate::error::PdsError::InvalidRecord(
            "rkey cannot be empty".into(),
        ));
    }
    if rkey.len() > MAX_RKEY_LEN {
        return Err(crate::error::PdsError::InvalidRecord(format!(
            "rkey exceeds max length of {MAX_RKEY_LEN}"
        )));
    }
    if rkey == "." || rkey == ".." {
        return Err(crate::error::PdsError::InvalidRecord(
            "rkey cannot be '.' or '..'".into(),
        ));
    }
    if !rkey
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._:~-".contains(&b))
    {
        return Err(crate::error::PdsError::InvalidRecord(
            "rkey contains invalid characters".into(),
        ));
    }
    Ok(())
}

/// Validates a collection name as a valid NSID.
///
/// A valid NSID has at least 3 dot-separated segments, each alphanumeric
/// (with hyphens allowed except at start/end). No path traversal.
pub fn validate_collection(collection: &str) -> crate::error::Result<()> {
    if collection.is_empty() {
        return Err(crate::error::PdsError::InvalidRecord(
            "collection cannot be empty".into(),
        ));
    }
    if collection.len() > MAX_COLLECTION_LEN {
        return Err(crate::error::PdsError::InvalidRecord(format!(
            "collection exceeds max length of {MAX_COLLECTION_LEN}"
        )));
    }
    // Must not contain path traversal sequences
    if collection.contains("..") || collection.contains('/') || collection.contains('\\') {
        return Err(crate::error::PdsError::InvalidRecord(
            "collection contains invalid characters".into(),
        ));
    }
    let segments: Vec<&str> = collection.split('.').collect();
    // NSID requires at least 3 segments (e.g., app.bsky.feed)
    if segments.len() < 3 {
        return Err(crate::error::PdsError::InvalidRecord(
            "collection must be a valid NSID with at least 3 segments".into(),
        ));
    }
    for seg in &segments {
        if seg.is_empty() {
            return Err(crate::error::PdsError::InvalidRecord(
                "collection has empty segment".into(),
            ));
        }
        if !seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(crate::error::PdsError::InvalidRecord(
                "collection segment contains invalid characters".into(),
            ));
        }
    }
    Ok(())
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

    #[test]
    fn test_validate_rkey_valid() {
        assert!(validate_rkey("abc123").is_ok());
        assert!(validate_rkey("3mewseimdh27m").is_ok());
        assert!(validate_rkey("self").is_ok());
        assert!(validate_rkey("a-b_c.d:e~f").is_ok());
    }

    #[test]
    fn test_validate_rkey_invalid() {
        assert!(validate_rkey("").is_err());
        assert!(validate_rkey(".").is_err());
        assert!(validate_rkey("..").is_err());
        assert!(validate_rkey("../../../etc/passwd").is_err());
        assert!(validate_rkey("test\0evil").is_err());
        assert!(validate_rkey("a/b").is_err());
        assert!(validate_rkey(&"x".repeat(513)).is_err());
    }

    #[test]
    fn test_validate_collection_valid() {
        assert!(validate_collection("app.bsky.feed.post").is_ok());
        assert!(validate_collection("app.bsky.feed.like").is_ok());
        assert!(validate_collection("app.bsky.actor.profile").is_ok());
        assert!(validate_collection("com.example.custom-type").is_ok());
    }

    #[test]
    fn test_validate_collection_invalid() {
        assert!(validate_collection("").is_err());
        assert!(validate_collection("post").is_err());
        assert!(validate_collection("a.b").is_err());
        assert!(validate_collection("../../../etc/passwd").is_err());
        assert!(validate_collection("com.evil..malware").is_err());
        assert!(validate_collection("com/evil/path").is_err());
    }
}
