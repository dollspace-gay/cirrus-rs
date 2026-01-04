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

    /// Creates an `InvalidRequest` error.
    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new("InvalidRequest", message)
    }

    /// Creates an `AuthenticationRequired` error.
    #[must_use]
    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::new("AuthenticationRequired", message)
    }

    /// Creates a `RecordNotFound` error.
    #[must_use]
    pub fn record_not_found(message: impl Into<String>) -> Self {
        Self::new("RecordNotFound", message)
    }

    /// Creates an `AccountDeactivated` error.
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

const fn default_true() -> bool {
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

/// Put record input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutRecordInput {
    /// Repository DID.
    pub repo: String,
    /// Collection name.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Record value.
    pub record: serde_json::Value,
    /// Validate the record.
    #[serde(default = "default_true")]
    pub validate: bool,
    /// Expected CID for swap (optional).
    #[serde(rename = "swapRecord", skip_serializing_if = "Option::is_none")]
    pub swap_record: Option<String>,
}

/// Put record output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutRecordOutput {
    /// AT URI of the record.
    pub uri: String,
    /// CID of the record.
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
    /// Expected CID for swap (optional).
    #[serde(rename = "swapRecord", skip_serializing_if = "Option::is_none")]
    pub swap_record: Option<String>,
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

/// Check account status output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAccountStatusOutput {
    /// Whether the account is activated.
    pub activated: bool,
    /// Whether the account is valid (DID exists, etc).
    #[serde(rename = "validDid")]
    pub valid_did: bool,
    /// The repo commit revision.
    #[serde(rename = "repoCommit", skip_serializing_if = "Option::is_none")]
    pub repo_commit: Option<String>,
    /// The repo root CID.
    #[serde(rename = "repoRev", skip_serializing_if = "Option::is_none")]
    pub repo_rev: Option<String>,
}

/// Deactivate account input.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeactivateAccountInput {
    /// Delete the account after deactivation.
    #[serde(rename = "deleteAfter", skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<String>,
}

/// Get preferences output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPreferencesOutput {
    /// Array of preference objects.
    pub preferences: Vec<serde_json::Value>,
}

/// Put preferences input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutPreferencesInput {
    /// Array of preference objects.
    pub preferences: Vec<serde_json::Value>,
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
