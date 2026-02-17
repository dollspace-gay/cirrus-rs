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

/// Create invite code input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteCodeInput {
    /// Number of uses for this code.
    #[serde(rename = "useCount", default = "default_one")]
    pub use_count: i64,
    /// Account to assign the invite code to (optional).
    #[serde(rename = "forAccount", skip_serializing_if = "Option::is_none")]
    pub for_account: Option<String>,
}

fn default_one() -> i64 {
    1
}

/// Create invite code output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteCodeOutput {
    /// The generated invite code.
    pub code: String,
}

/// Create invite codes (batch) input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteCodesInput {
    /// Number of codes to create.
    #[serde(rename = "codeCount", default = "default_one")]
    pub code_count: i64,
    /// Number of uses per code.
    #[serde(rename = "useCount", default = "default_one")]
    pub use_count: i64,
    /// Accounts to assign codes to (optional).
    #[serde(rename = "forAccounts", skip_serializing_if = "Option::is_none")]
    pub for_accounts: Option<Vec<String>>,
}

/// Create invite codes output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInviteCodesOutput {
    /// The generated codes.
    pub codes: Vec<AccountCodes>,
}

/// Account-to-code mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCodes {
    /// Account DID.
    pub account: String,
    /// The generated codes.
    pub codes: Vec<String>,
}

/// Get account invite codes output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccountInviteCodesOutput {
    /// The invite codes.
    pub codes: Vec<InviteCodeInfo>,
}

/// Invite code info for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCodeInfo {
    /// The code string.
    pub code: String,
    /// Number of available uses.
    #[serde(rename = "availableUses")]
    pub available_uses: i64,
    /// Whether the code is disabled.
    pub disabled: bool,
    /// Account this code is for.
    #[serde(rename = "forAccount")]
    pub for_account: String,
    /// Who created the code.
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// When the code was created.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// List of uses.
    pub uses: Vec<serde_json::Value>,
}

/// Reserve signing key input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveSigningKeyInput {
    /// The DID to reserve the key for (optional).
    pub did: Option<String>,
}

/// Reserve signing key output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReserveSigningKeyOutput {
    /// The reserved signing key in DID key format.
    #[serde(rename = "signingKey")]
    pub signing_key: String,
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

// ── Repo migration types ─────────────────────────────────────────────

/// List missing blobs output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMissingBlobsOutput {
    /// List of missing blob references.
    pub blobs: Vec<MissingBlobRef>,
    /// Pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// A reference to a missing blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingBlobRef {
    /// CID of the missing blob.
    pub cid: String,
    /// Record AT-URI that references this blob.
    #[serde(rename = "recordUri")]
    pub record_uri: String,
}

// ── Admin API types ──────────────────────────────────────────────────

/// Admin: get account info query params.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminGetAccountInfoParams {
    /// DID of the account.
    pub did: String,
}

/// Admin: account info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminAccountInfo {
    /// Account DID.
    pub did: String,
    /// Account handle.
    pub handle: String,
    /// Account email (if set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether email is confirmed.
    #[serde(rename = "emailConfirmedAt", skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    /// When the account was indexed.
    #[serde(rename = "indexedAt")]
    pub indexed_at: String,
    /// Invite code used to create the account.
    #[serde(rename = "invitedBy", skip_serializing_if = "Option::is_none")]
    pub invited_by: Option<serde_json::Value>,
    /// Invite codes created by this account.
    #[serde(rename = "invites", skip_serializing_if = "Option::is_none")]
    pub invites: Option<Vec<InviteCodeInfo>>,
    /// Whether invites are disabled for this account.
    #[serde(rename = "invitesDisabled", skip_serializing_if = "Option::is_none")]
    pub invites_disabled: Option<bool>,
    /// Account deactivation info.
    #[serde(rename = "deactivatedAt", skip_serializing_if = "Option::is_none")]
    pub deactivated_at: Option<String>,
}

/// Admin: get account infos input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminGetAccountInfosParams {
    /// List of DIDs to look up.
    pub dids: Vec<String>,
}

/// Admin: get account infos output.
#[derive(Debug, Clone, Serialize)]
pub struct AdminGetAccountInfosOutput {
    /// Account info list.
    pub infos: Vec<AdminAccountInfo>,
}

/// Subject status reference (a DID or AT-URI + CID).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSubjectStatus {
    /// Subject (DID or AT-URI).
    pub subject: serde_json::Value,
    /// Takedown reference (if taken down).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takedown: Option<AdminStatusAttr>,
    /// Deactivation info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<AdminStatusAttr>,
}

/// A status attribute with an applied flag and optional reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStatusAttr {
    /// Whether the status is applied.
    pub applied: bool,
    /// Optional reference string (e.g. moderation report ID).
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// Admin: get subject status query params.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminGetSubjectStatusParams {
    /// Subject DID.
    #[serde(default)]
    pub did: Option<String>,
    /// Subject AT-URI.
    #[serde(default)]
    pub uri: Option<String>,
    /// Subject blob CID.
    #[serde(default)]
    pub blob: Option<String>,
}

/// Admin: update subject status input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateSubjectStatusInput {
    /// The subject.
    pub subject: serde_json::Value,
    /// Takedown status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takedown: Option<AdminStatusAttr>,
    /// Deactivation status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<AdminStatusAttr>,
}

/// Admin: update subject status output.
#[derive(Debug, Clone, Serialize)]
pub struct AdminUpdateSubjectStatusOutput {
    /// The subject.
    pub subject: serde_json::Value,
    /// Takedown status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takedown: Option<AdminStatusAttr>,
}

/// Admin: send email input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminSendEmailInput {
    /// Recipient DID.
    #[serde(rename = "recipientDid")]
    pub recipient_did: String,
    /// Email subject line.
    pub subject: String,
    /// Email body content.
    pub content: String,
    /// Sender DID.
    #[serde(rename = "senderDid")]
    pub sender_did: String,
}

/// Admin: send email output.
#[derive(Debug, Clone, Serialize)]
pub struct AdminSendEmailOutput {
    /// Whether the email was sent.
    pub sent: bool,
}

/// Admin: update account email input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateAccountEmailInput {
    /// Account DID.
    pub account: String,
    /// New email address.
    pub email: String,
}

/// Admin: update account handle input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateAccountHandleInput {
    /// Account DID.
    pub did: String,
    /// New handle.
    pub handle: String,
}

/// Admin: update account password input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminUpdateAccountPasswordInput {
    /// Account DID.
    pub did: String,
    /// New password.
    pub password: String,
}

/// Admin: delete account input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminDeleteAccountInput {
    /// Account DID.
    pub did: String,
}

/// Admin: disable/enable account invites input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminAccountInvitesInput {
    /// Account DID.
    pub account: String,
}

/// Admin: disable invite codes input.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminDisableInviteCodesInput {
    /// Codes to disable.
    #[serde(default)]
    pub codes: Vec<String>,
    /// Accounts whose codes should be disabled.
    #[serde(default)]
    pub accounts: Vec<String>,
}

/// Admin: get invite codes query params.
#[derive(Debug, Clone, Deserialize)]
pub struct AdminGetInviteCodesParams {
    /// Sort order.
    #[serde(default)]
    pub sort: Option<String>,
    /// Max results.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Pagination cursor.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// Admin: get invite codes output.
#[derive(Debug, Clone, Serialize)]
pub struct AdminGetInviteCodesOutput {
    /// Invite codes.
    pub codes: Vec<InviteCodeInfo>,
    /// Pagination cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
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
