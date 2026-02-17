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

/// Get service auth output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetServiceAuthOutput {
    /// Signed service JWT token.
    pub token: String,
}

/// Apply writes input — batch multiple create/update/delete operations atomically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyWritesInput {
    /// Repository DID.
    pub repo: String,
    /// Whether to validate records against lexicon schemas.
    #[serde(default = "default_true")]
    pub validate: bool,
    /// Batch of write operations (max 200).
    pub writes: Vec<ApplyWriteOp>,
    /// Expected commit CID for optimistic concurrency (optional).
    #[serde(rename = "swapCommit", skip_serializing_if = "Option::is_none")]
    pub swap_commit: Option<String>,
}

/// Maximum number of writes in a single applyWrites call.
pub const MAX_APPLY_WRITES: usize = 200;

/// A single write operation within an applyWrites batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum ApplyWriteOp {
    /// Create a new record.
    #[serde(rename = "com.atproto.repo.applyWrites#create")]
    Create {
        /// Collection NSID.
        collection: String,
        /// Record key (optional, auto-generated if omitted).
        rkey: Option<String>,
        /// Record value.
        value: serde_json::Value,
    },
    /// Update an existing record.
    #[serde(rename = "com.atproto.repo.applyWrites#update")]
    Update {
        /// Collection NSID.
        collection: String,
        /// Record key.
        rkey: String,
        /// Record value.
        value: serde_json::Value,
    },
    /// Delete a record.
    #[serde(rename = "com.atproto.repo.applyWrites#delete")]
    Delete {
        /// Collection NSID.
        collection: String,
        /// Record key.
        rkey: String,
    },
}

/// Apply writes output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyWritesOutput {
    /// Commit metadata.
    pub commit: ApplyWritesCommit,
    /// Results for each write operation, in input order.
    pub results: Vec<ApplyWriteResult>,
}

/// Commit metadata in apply writes response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyWritesCommit {
    /// Commit CID.
    pub cid: String,
    /// Revision.
    pub rev: String,
}

/// Result of a single write operation within applyWrites.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ApplyWriteResult {
    /// Result of a create operation.
    CreateResult {
        /// AT URI of created record.
        uri: String,
        /// CID of created record.
        cid: String,
    },
    /// Result of an update operation.
    UpdateResult {
        /// AT URI of updated record.
        uri: String,
        /// CID of updated record.
        cid: String,
    },
    /// Result of a delete operation (empty object).
    DeleteResult {},
}

/// Create app password input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAppPasswordInput {
    /// User-assigned name for this app password.
    pub name: String,
    /// Whether this password should have privileged access.
    #[serde(default)]
    pub privileged: bool,
}

/// Create app password output (includes the plaintext password, shown once).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAppPasswordOutput {
    /// User-assigned name.
    pub name: String,
    /// The generated app password (plaintext, shown only once).
    pub password: String,
    /// Whether this password has privileged access.
    pub privileged: bool,
    /// When the password was created (ISO 8601).
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// List app passwords output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAppPasswordsOutput {
    /// App password entries (without plaintext passwords).
    pub passwords: Vec<AppPasswordInfo>,
}

/// App password info (never includes the hash or plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPasswordInfo {
    /// User-assigned name.
    pub name: String,
    /// Whether this password has privileged access.
    pub privileged: bool,
    /// When the password was created (ISO 8601).
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Revoke app password input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeAppPasswordInput {
    /// Name of the app password to revoke.
    pub name: String,
}

/// Update handle input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateHandleInput {
    /// The new handle.
    pub handle: String,
}

/// Create account input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountInput {
    /// Requested handle for the account.
    pub handle: String,
    /// Initial account password.
    pub password: String,
    /// Email address (optional).
    pub email: Option<String>,
    /// Invite code (optional, ignored for single-user PDS).
    #[serde(rename = "inviteCode", skip_serializing_if = "Option::is_none")]
    pub invite_code: Option<String>,
    /// Recovery key for DID PLC (optional).
    #[serde(rename = "recoveryKey", skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<String>,
}

/// Create account output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAccountOutput {
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

/// Recommended DID credentials output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecommendedDidCredentialsOutput {
    /// Recommended rotation keys (multibase-encoded).
    #[serde(rename = "rotationKeys", skip_serializing_if = "Option::is_none")]
    pub rotation_keys: Option<Vec<String>>,
    /// Also-known-as identifiers (handles as at:// URIs).
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    /// Verification methods (keys).
    #[serde(
        rename = "verificationMethods",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_methods: Option<serde_json::Value>,
    /// Service endpoints.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<serde_json::Value>,
}

/// Sign PLC operation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignPlcOperationInput {
    /// Token from `requestPlcOperationSignature`.
    pub token: Option<String>,
    /// Rotation keys (optional override).
    #[serde(rename = "rotationKeys", skip_serializing_if = "Option::is_none")]
    pub rotation_keys: Option<Vec<String>>,
    /// Also-known-as identifiers (optional override).
    #[serde(rename = "alsoKnownAs", skip_serializing_if = "Option::is_none")]
    pub also_known_as: Option<Vec<String>>,
    /// Verification methods (optional override).
    #[serde(
        rename = "verificationMethods",
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_methods: Option<serde_json::Value>,
    /// Service endpoints (optional override).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<serde_json::Value>,
}

/// Sign PLC operation output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignPlcOperationOutput {
    /// The signed PLC operation.
    pub operation: serde_json::Value,
}

/// Submit PLC operation input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPlcOperationInput {
    /// The signed PLC operation to submit.
    pub operation: serde_json::Value,
}

/// Request password reset input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPasswordResetInput {
    /// Email address of the account.
    pub email: String,
}

/// Reset password input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordInput {
    /// The email token from the reset request.
    pub token: String,
    /// The new password.
    pub password: String,
}

/// Confirm email input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmEmailInput {
    /// Email address being confirmed.
    pub email: String,
    /// The confirmation token.
    pub token: String,
}

/// Update email input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEmailInput {
    /// The new email address.
    pub email: String,
    /// The confirmation token.
    pub token: String,
}

/// Create moderation report input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportInput {
    /// Type of reason for the report.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Additional context/description (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The subject being reported (a repo or record reference).
    pub subject: serde_json::Value,
}

/// Create moderation report output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportOutput {
    /// Report ID.
    pub id: i64,
    /// Type of reason for the report.
    #[serde(rename = "reasonType")]
    pub reason_type: String,
    /// Additional context/description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The subject being reported.
    pub subject: serde_json::Value,
    /// DID of the reporter.
    #[serde(rename = "reportedBy")]
    pub reported_by: String,
    /// Timestamp of the report.
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Delete account input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteAccountInput {
    /// The account DID.
    pub did: String,
    /// The account password.
    pub password: String,
    /// The deletion confirmation token.
    pub token: String,
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
