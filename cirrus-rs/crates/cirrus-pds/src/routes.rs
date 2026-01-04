//! XRPC route handlers for AT Protocol PDS.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;

use crate::error::PdsError;
use crate::lexicon::LexiconStore;
use crate::middleware::{RequireAdmin, RequireAuth};
use crate::repo::{generate_rkey, make_at_uri};
use crate::sequencer::Firehose;
use crate::storage::SqliteStorage;
use crate::xrpc::{
    CheckAccountStatusOutput, CreateRecordInput, CreateRecordOutput, CreateSessionInput,
    DeactivateAccountInput, DescribeRepoOutput, GetPreferencesOutput, GetRecordOutput,
    ListRecordEntry, ListRecordsOutput, PutPreferencesInput, PutRecordInput, PutRecordOutput,
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
    /// Firehose broadcast channel.
    pub firehose: Firehose,
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
        // Actor endpoints
        .route("/xrpc/app.bsky.actor.getPreferences", get(get_preferences))
        .route("/xrpc/app.bsky.actor.putPreferences", post(put_preferences))
        // Repo endpoints
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        // Sync endpoints
        .route("/xrpc/com.atproto.sync.getHead", get(get_head))
        .route("/xrpc/com.atproto.sync.getLatestCommit", get(get_latest_commit))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.subscribeRepos", get(subscribe_repos))
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

/// Query parameters for getLatestCommit.
#[derive(Debug, Deserialize)]
pub struct GetLatestCommitParams {
    /// Repository DID.
    pub did: String,
}

/// Query parameters for getBlob.
#[derive(Debug, Deserialize)]
pub struct GetBlobParams {
    /// Repository DID.
    pub did: String,
    /// Blob CID.
    pub cid: String,
}

/// Query parameters for getRepo.
#[derive(Debug, Deserialize)]
pub struct GetRepoParams {
    /// Repository DID.
    pub did: String,
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

async fn get_preferences(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
) -> Response {
    match state.storage.get_preferences() {
        Ok(prefs) => Json(GetPreferencesOutput { preferences: prefs }).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn put_preferences(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Json(input): Json<PutPreferencesInput>,
) -> Response {
    if let Err(e) = state.storage.put_preferences(&input.preferences) {
        return e.into_response();
    }
    StatusCode::OK.into_response()
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
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListRecordsParams>,
) -> Response {
    if params.repo != state.did && params.repo != state.handle {
        return PdsError::RepoNotFound(params.repo).into_response();
    }

    let limit = params.limit.unwrap_or(50).min(100);
    let reverse = params.reverse.unwrap_or(false);

    let entries = match state.storage.list_records(
        &params.collection,
        limit,
        params.cursor.as_deref(),
        reverse,
    ) {
        Ok(e) => e,
        Err(e) => return e.into_response(),
    };

    let mut records = Vec::with_capacity(entries.len());
    for entry in &entries {
        let value: serde_json::Value = match cirrus_common::cbor::decode(&entry.bytes) {
            Ok(v) => v,
            Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
        };
        let cid = cirrus_common::cid::Cid::for_cbor(&entry.bytes).to_string();
        let uri = make_at_uri(&state.did, &params.collection, &entry.rkey);
        records.push(ListRecordEntry { uri, cid, value });
    }

    let cursor = if records.len() == limit as usize {
        entries.last().map(|e| e.rkey.clone())
    } else {
        None
    };

    Json(ListRecordsOutput { records, cursor }).into_response()
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

async fn put_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    Json(input): Json<PutRecordInput>,
) -> Response {
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

    // Check swap_record if provided (optimistic concurrency)
    let block_key = format!("{}:{}", input.collection, input.rkey);
    if let Some(ref expected_cid) = input.swap_record {
        match state.storage.get_block(&block_key) {
            Ok(Some(existing)) => {
                let current_cid = cirrus_common::cid::Cid::for_cbor(&existing).to_string();
                if &current_cid != expected_cid {
                    return PdsError::InvalidRecord("swap_record CID mismatch".into()).into_response();
                }
            }
            Ok(None) => {
                return PdsError::RecordNotFound(block_key).into_response();
            }
            Err(e) => return e.into_response(),
        }
    }

    if input.validate {
        if let Err(e) = state.lexicons.validate_record(&input.collection, &input.record) {
            return e.into_response();
        }
    }

    let cbor_bytes = match cirrus_common::cbor::encode(&input.record) {
        Ok(b) => b,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    let cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes).to_string();

    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = state.storage.put_block(&block_key, &cbor_bytes, repo_state.rev.as_deref()) {
        return e.into_response();
    }

    let uri = make_at_uri(&auth.did, &input.collection, &input.rkey);

    Json(PutRecordOutput { uri, cid }).into_response()
}

async fn delete_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    Json(input): Json<crate::xrpc::DeleteRecordInput>,
) -> Response {
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

    let block_key = format!("{}:{}", input.collection, input.rkey);

    // Check swap_record if provided
    if let Some(ref expected_cid) = input.swap_record {
        match state.storage.get_block(&block_key) {
            Ok(Some(existing)) => {
                let current_cid = cirrus_common::cid::Cid::for_cbor(&existing).to_string();
                if &current_cid != expected_cid {
                    return PdsError::InvalidRecord("swap_record CID mismatch".into()).into_response();
                }
            }
            Ok(None) => {
                return PdsError::RecordNotFound(block_key).into_response();
            }
            Err(e) => return e.into_response(),
        }
    }

    match state.storage.delete_block(&block_key) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => PdsError::RecordNotFound(block_key).into_response(),
        Err(e) => e.into_response(),
    }
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

async fn get_latest_commit(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetLatestCommitParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    match state.storage.get_repo_state() {
        Ok(repo_state) => Json(serde_json::json!({
            "cid": repo_state.root_cid,
            "rev": repo_state.rev
        })).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_blob(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetBlobParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    match state.storage.get_block(&params.cid) {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        ).into_response(),
        Ok(None) => PdsError::RecordNotFound(format!("blob not found: {}", params.cid)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_repo(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetRepoParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    let blocks = match state.storage.get_all_blocks() {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    let root_cid = match repo_state.root_cid {
        Some(ref cid_str) => cirrus_common::cid::Cid::from_string(cid_str)
            .unwrap_or_else(|_| cirrus_common::cid::Cid::for_cbor(&[])),
        None => cirrus_common::cid::Cid::for_cbor(&[]),
    };

    let mut car_buf = Vec::new();
    let mut writer = match cirrus_common::car::CarWriter::new(&mut car_buf, root_cid) {
        Ok(w) => w,
        Err(e) => return PdsError::InvalidRecord(format!("CAR header error: {e}")).into_response(),
    };

    for block in blocks {
        let cid = cirrus_common::cid::Cid::for_cbor(&block.bytes);
        if let Err(e) = writer.write_block(&cid, &block.bytes) {
            return PdsError::InvalidRecord(format!("CAR block error: {e}")).into_response();
        }
    }

    drop(writer);

    (
        StatusCode::OK,
        [("content-type", "application/vnd.ipld.car")],
        car_buf,
    ).into_response()
}

async fn subscribe_repos(
    State(state): State<Arc<AppState>>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(|socket| handle_firehose(socket, state))
}

async fn handle_firehose(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.firehose.subscribe();

    // Use a channel to signal when receiver closes
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn task to handle incoming messages (for cursor requests, etc.)
    tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // Ignore other messages
                Err(_) => break,
            }
        }
        let _ = close_tx.send(());
    });

    // Send events to the client
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        match event.encode() {
                            Ok(bytes) => {
                                if sender.send(Message::Binary(bytes.into())).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Client fell behind, continue
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            _ = &mut close_rx => {
                break;
            }
        }
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
            firehose: Firehose::new(),
        });

        let _router = create_router(state);
    }
}
