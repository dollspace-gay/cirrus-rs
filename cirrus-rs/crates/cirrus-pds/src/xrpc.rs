//! XRPC endpoint handlers.

use serde::{Deserialize, Serialize};

/// XRPC error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrpcError {
    /// Error code.
    pub error: String,
    /// Error message.
    pub message: String,
}

impl XrpcError {
    /// Creates a new XRPC error.
    #[must_use]
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }

    /// Creates an InvalidRequest error.
    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("InvalidRequest", message)
    }

    /// Creates an AuthenticationRequired error.
    #[must_use]
    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::new("AuthenticationRequired", message)
    }

    /// Creates a RecordNotFound error.
    #[must_use]
    pub fn record_not_found(message: impl Into<String>) -> Self {
        Self::new("RecordNotFound", message)
    }

    /// Creates an AccountDeactivated error.
    #[must_use]
    pub fn account_deactivated() -> Self {
        Self::new("AccountDeactivated", "Account is deactivated")
    }
}

/// Describe repo response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescribeRepoOutput {
    /// Repository handle.
    pub handle: String,
    /// Repository DID.
    pub did: String,
    /// DID document.
    #[serde(rename = "didDoc")]
    pub did_doc: serde_json::Value,
    /// Collections in the repo.
    pub collections: Vec<String>,
    /// Whether handle is correct.
    #[serde(rename = "handleIsCorrect")]
    pub handle_is_correct: bool,
}

/// Get record response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecordOutput {
    /// AT URI.
    pub uri: String,
    /// Record CID.
    pub cid: String,
    /// Record value.
    pub value: serde_json::Value,
}

/// Create record input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRecordInput {
    /// Repository DID.
    pub repo: String,
    /// Collection name.
    pub collection: String,
    /// Record key (optional, will be generated if not provided).
    pub rkey: Option<String>,
    /// Record value.
    pub record: serde_json::Value,
    /// Validate the record.
    #[serde(default = "default_true")]
    pub validate: bool,
}

fn default_true() -> bool {
    true
}

/// Create record output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRecordOutput {
    /// AT URI of created record.
    pub uri: String,
    /// CID of created record.
    pub cid: String,
}

/// Delete record input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRecordInput {
    /// Repository DID.
    pub repo: String,
    /// Collection name.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

/// List records output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRecordsOutput {
    /// Records.
    pub records: Vec<ListRecordEntry>,
    /// Cursor for pagination.
    pub cursor: Option<String>,
}

/// A record entry in list records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListRecordEntry {
    /// AT URI.
    pub uri: String,
    /// Record CID.
    pub cid: String,
    /// Record value.
    pub value: serde_json::Value,
}

/// Create session input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionInput {
    /// Handle or DID.
    pub identifier: String,
    /// Password.
    pub password: String,
}

/// Session output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOutput {
    /// Access JWT.
    #[serde(rename = "accessJwt")]
    pub access_jwt: String,
    /// Refresh JWT.
    #[serde(rename = "refreshJwt")]
    pub refresh_jwt: String,
    /// Handle.
    pub handle: String,
    /// DID.
    pub did: String,
}

/// Upload blob output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadBlobOutput {
    /// Blob reference.
    pub blob: crate::blobs::BlobRef,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xrpc_error() {
        let error = XrpcError::invalid_request("missing parameter");
        assert_eq!(error.error, "InvalidRequest");
    }

    #[test]
    fn test_create_record_input_defaults() {
        let json = r#"{"repo": "did:plc:test", "collection": "test", "record": {}}"#;
        let input: CreateRecordInput = serde_json::from_str(json).unwrap();

        assert!(input.validate);
        assert!(input.rkey.is_none());
    }
}
