//! XRPC route handlers for AT Protocol PDS.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::error::PdsError;
use crate::lexicon::LexiconStore;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::repo::{generate_rkey, make_at_uri};
use crate::storage::SqliteStorage;
use crate::xrpc::{
    CheckAccountStatusOutput, CreateRecordInput, CreateRecordOutput, CreateSessionInput,
    DeactivateAccountInput, DescribeRepoOutput, GetRecordOutput, ListRecordsOutput,
    SessionOutput, XrpcError,
};

/// Application state shared across handlers.
pub struct AppState {
    /// Repository storage.
    pub storage: SqliteStorage,
    /// Lexicon store for validation.
    pub lexicons: LexiconStore,
    /// JWT secret for session tokens.
    pub jwt_secret: Vec<u8>,
    /// This PDS's hostname.
    pub hostname: String,
    /// DID of the account.
    pub did: String,
    /// Handle of the account.
    pub handle: String,
    /// Public key in multibase format for DID document.
    pub public_key_multibase: String,
}

/// Creates the XRPC router.
#[must_use = "returns the configured router"]
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Server endpoints
        .route("/xrpc/com.atproto.server.describeServer", get(describe_server))
        .route("/xrpc/com.atproto.server.createSession", post(create_session))
        .route("/xrpc/com.atproto.server.refreshSession", post(refresh_session))
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route("/xrpc/com.atproto.server.deleteSession", post(delete_session))
        .route("/xrpc/com.atproto.server.activateAccount", post(activate_account))
        .route("/xrpc/com.atproto.server.deactivateAccount", post(deactivate_account))
        .route("/xrpc/com.atproto.server.checkAccountStatus", get(check_account_status))
        // Repo endpoints
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        // Sync endpoints
        .route("/xrpc/com.atproto.sync.getHead", get(get_head))
        // Identity endpoints
        .route("/xrpc/com.atproto.identity.resolveHandle", get(resolve_handle))
        // Health check
        .route("/health", get(health_check))
        .route("/.well-known/atproto-did", get(well_known_did))
        .with_state(state)
}

/// Query parameters for describeRepo.
#[derive(Debug, Deserialize)]
pub struct DescribeRepoParams {
    /// Repository DID or handle.
    pub repo: String,
}

/// Query parameters for getRecord.
#[derive(Debug, Deserialize)]
pub struct GetRecordParams {
    /// Repository DID or handle.
    pub repo: String,
    /// Collection name.
    pub collection: String,
    /// Record key.
    pub rkey: String,
}

/// Query parameters for listRecords.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ListRecordsParams {
    /// Repository DID or handle.
    pub repo: String,
    /// Collection name.
    pub collection: String,
    /// Maximum number of records.
    pub limit: Option<u32>,
    /// Pagination cursor.
    pub cursor: Option<String>,
    /// Return records in reverse order.
    pub reverse: Option<bool>,
}

/// Query parameters for resolveHandle.
#[derive(Debug, Deserialize)]
pub struct ResolveHandleParams {
    /// Handle to resolve.
    pub handle: String,
}

// ============================================================================
// Handler implementations
// ============================================================================

async fn health_check() -> &'static str {
    "OK"
}

async fn well_known_did(State(state): State<Arc<AppState>>) -> String {
    state.did.clone()
}

async fn describe_server(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "availableUserDomains": [],
        "inviteCodeRequired": false,
        "did": format!("did:web:{}", state.hostname),
        "links": {}
    }))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    match crate::auth::create_session(&input.identifier, &input.password, &state.jwt_secret) {
        Ok(tokens) => Json(SessionOutput {
            access_jwt: tokens.access_jwt,
            refresh_jwt: tokens.refresh_jwt,
            handle: state.handle.clone(),
            did: state.did.clone(),
        }).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn refresh_session(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Response {
    // Use the DID from the refresh token
    match crate::auth::refresh_tokens(&auth.did, &state.jwt_secret) {
        Ok(tokens) => Json(SessionOutput {
            access_jwt: tokens.access_jwt,
            refresh_jwt: tokens.refresh_jwt,
            handle: state.handle.clone(),
            did: auth.did,
        }).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "handle": state.handle,
        "did": auth.did,
        "active": true
    }))
}

async fn delete_session(
    RequireAuth(_auth): RequireAuth,
) -> StatusCode {
    // In a full implementation, would invalidate the session
    StatusCode::OK
}

async fn activate_account(
    State(state): State<Arc<AppState>>,
    RequireAdmin(_auth): RequireAdmin,
) -> Response {
    if let Err(e) = state.storage.set_active(true) {
        return e.into_response();
    }
    StatusCode::OK.into_response()
}

async fn deactivate_account(
    State(state): State<Arc<AppState>>,
    RequireAdmin(_auth): RequireAdmin,
    Json(_input): Json<DeactivateAccountInput>,
) -> Response {
    if let Err(e) = state.storage.set_active(false) {
        return e.into_response();
    }
    StatusCode::OK.into_response()
}

async fn check_account_status(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
) -> Response {
    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    Json(CheckAccountStatusOutput {
        activated: repo_state.active,
        valid_did: !state.did.is_empty(),
        repo_commit: repo_state.root_cid,
        repo_rev: repo_state.rev,
    }).into_response()
}

async fn describe_repo(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DescribeRepoParams>,
) -> Response {
    if params.repo != state.did && params.repo != state.handle {
        return PdsError::RepoNotFound(params.repo).into_response();
    }

    let did_doc = crate::did::create_did_document(
        &state.did,
        &state.handle,
        &format!("https://{}", state.hostname),
        &state.public_key_multibase,
    );

    let did_doc_value = match serde_json::to_value(&did_doc) {
        Ok(v) => v,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    Json(DescribeRepoOutput {
        handle: state.handle.clone(),
        did: state.did.clone(),
        did_doc: did_doc_value,
        collections: vec![
            "app.bsky.feed.post".to_string(),
            "app.bsky.feed.like".to_string(),
            "app.bsky.feed.repost".to_string(),
            "app.bsky.graph.follow".to_string(),
            "app.bsky.actor.profile".to_string(),
        ],
        handle_is_correct: true,
    }).into_response()
}

async fn get_record(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetRecordParams>,
) -> Response {
    let uri = make_at_uri(&state.did, &params.collection, &params.rkey);

    let block_cid = format!("{}:{}", params.collection, params.rkey);
    let block = match state.storage.get_block(&block_cid) {
        Ok(Some(b)) => b,
        Ok(None) => return PdsError::RecordNotFound(uri).into_response(),
        Err(e) => return e.into_response(),
    };

    let value: serde_json::Value = match cirrus_common::cbor::decode(&block) {
        Ok(v) => v,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    let cid = cirrus_common::cid::Cid::for_cbor(&block).to_string();

    Json(GetRecordOutput { uri, cid, value }).into_response()
}

async fn list_records(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<ListRecordsParams>,
) -> Json<ListRecordsOutput> {
    Json(ListRecordsOutput {
        records: vec![],
        cursor: None,
    })
}

async fn create_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    // RequireAdmin already verified the user is the PDS owner
    if input.repo != auth.did {
        return PdsError::NotAuthorized("repo mismatch".into()).into_response();
    }

    let is_active = match state.storage.is_active() {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !is_active {
        return PdsError::AccountDeactivated.into_response();
    }

    if input.validate {
        if let Err(e) = state.lexicons.validate_record(&input.collection, &input.record) {
            return e.into_response();
        }
    }

    let rkey = input.rkey.unwrap_or_else(generate_rkey);

    let cbor_bytes = match cirrus_common::cbor::encode(&input.record) {
        Ok(b) => b,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    let cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes).to_string();

    let block_key = format!("{}:{}", input.collection, rkey);
    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = state.storage.put_block(&block_key, &cbor_bytes, repo_state.rev.as_deref()) {
        return e.into_response();
    }

    let uri = make_at_uri(&auth.did, &input.collection, &rkey);

    Json(CreateRecordOutput { uri, cid }).into_response()
}

async fn delete_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    Json(input): Json<crate::xrpc::DeleteRecordInput>,
) -> Response {
    // RequireAdmin already verified the user is the PDS owner
    if input.repo != auth.did {
        return PdsError::NotAuthorized("repo mismatch".into()).into_response();
    }

    let is_active = match state.storage.is_active() {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !is_active {
        return PdsError::AccountDeactivated.into_response();
    }

    StatusCode::OK.into_response()
}

async fn get_head(
    State(state): State<Arc<AppState>>,
) -> Response {
    match state.storage.get_repo_state() {
        Ok(repo_state) => Json(serde_json::json!({
            "root": repo_state.root_cid
        })).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn resolve_handle(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ResolveHandleParams>,
) -> Response {
    if params.handle == state.handle {
        Json(serde_json::json!({
            "did": state.did
        })).into_response()
    } else {
        PdsError::DidResolution(format!("handle not found: {}", params.handle)).into_response()
    }
}

// ============================================================================
// Error handling
// ============================================================================

impl IntoResponse for PdsError {
    fn into_response(self) -> axum::response::Response {
        let (status, error) = match &self {
            Self::RepoNotFound(_) => (StatusCode::NOT_FOUND, XrpcError::new("RepoNotFound", self.to_string())),
            Self::RecordNotFound(_) => (StatusCode::NOT_FOUND, XrpcError::record_not_found(self.to_string())),
            Self::InvalidRecord(_) | Self::Lexicon(_) | Self::Validation(_) => {
                (StatusCode::BAD_REQUEST, XrpcError::invalid_request(self.to_string()))
            }
            Self::AuthFailed(_) => (StatusCode::UNAUTHORIZED, XrpcError::auth_required(self.to_string())),
            Self::NotAuthorized(_) => (StatusCode::FORBIDDEN, XrpcError::new("NotAuthorized", self.to_string())),
            Self::AccountDeactivated => (StatusCode::FORBIDDEN, XrpcError::account_deactivated()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, XrpcError::new("RateLimited", "Too many requests")),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, XrpcError::new("InternalError", self.to_string())),
        };

        (status, Json(error)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_creation() {
        let storage = SqliteStorage::in_memory().unwrap();
        let state = Arc::new(AppState {
            storage,
            lexicons: LexiconStore::new(),
            jwt_secret: b"test-secret".to_vec(),
            hostname: "test.local".to_string(),
            did: "did:plc:test".to_string(),
            handle: "test.local".to_string(),
            public_key_multibase: "zQ3shtest".to_string(),
        });

        let _router = create_router(state);
    }
}
