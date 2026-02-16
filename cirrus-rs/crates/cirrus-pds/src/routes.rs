//! XRPC route handlers for AT Protocol PDS.

use std::net::IpAddr;
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

use crate::blobs::BlobStore;
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
    SessionOutput, UploadBlobOutput, XrpcError,
};

/// Application state shared across handlers.
pub struct AppState {
    /// Repository storage.
    pub storage: SqliteStorage,
    /// Lexicon store for validation.
    pub lexicons: LexiconStore,
    /// JWT secret for session tokens.
    pub jwt_secret: Vec<u8>,
    /// Bcrypt hash of the account password.
    pub password_hash: String,
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
    /// Blob storage backend.
    pub blob_store: Box<dyn BlobStore>,
    /// Handle resolver for non-local handles.
    pub handle_resolver: crate::handle::HandleResolver,
    /// Rate limiter state (None to disable rate limiting).
    pub rate_limits: Option<crate::rate_limit::RateLimitState>,
    /// OAuth token storage for DPoP-bound tokens (None to disable OAuth).
    pub oauth_storage: Option<crate::oauth_storage::OAuthSqliteStorage>,
    /// Signing keypair for commit signatures (None if not configured).
    pub signing_key: Option<cirrus_common::crypto::Keypair>,
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
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
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
        .route("/.well-known/did.json", get(well_known_did_json))
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

/// Extracts the client IP from request headers, falling back to localhost.
fn client_ip_from_headers(headers: &axum::http::HeaderMap) -> IpAddr {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
}

async fn health_check() -> &'static str {
    "OK"
}

async fn well_known_did(State(state): State<Arc<AppState>>) -> String {
    state.did.clone()
}

/// Serves the DID document for `did:web` resolution.
async fn well_known_did_json(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let doc = crate::did::create_did_document(
        &state.did,
        &state.handle,
        &format!("https://{}", state.hostname),
        &state.public_key_multibase,
    );
    Json(serde_json::to_value(doc).unwrap_or_default())
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
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateSessionInput>,
) -> Response {
    // Apply login rate limiting if enabled
    if let Some(rate_limits) = &state.rate_limits {
        let ip = client_ip_from_headers(&headers);
        if let Err(e) = crate::rate_limit::check_rate_limit(&rate_limits.login, ip) {
            return e.into_response();
        }
    }

    let config = crate::auth::SessionConfig {
        did: &state.did,
        handle: &state.handle,
        password_hash: &state.password_hash,
        jwt_secret: &state.jwt_secret,
    };

    match crate::auth::create_session(&input.identifier, &input.password, &config) {
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
    headers: axum::http::HeaderMap,
) -> Response {
    // Manually extract auth to allow refresh-scoped tokens
    let app_state = &*state;
    let parts_result = axum::http::Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.server.refreshSession");
    let mut builder = parts_result;
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    let (parts, _) = match builder.body(()) {
        Ok(req) => req.into_parts(),
        Err(_) => return crate::error::PdsError::AuthFailed("bad request".into()).into_response(),
    };
    let auth = match crate::middleware::extract_auth_for_refresh(&parts, app_state) {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };

    // Verify this is a refresh token
    if auth.scope != "atproto:refresh" {
        return crate::error::PdsError::AuthFailed(
            "refresh endpoint requires a refresh token".into(),
        )
        .into_response();
    }

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

/// Builds a DAG-CBOR commit object, optionally signed with a secp256k1 key.
///
/// The commit follows the AT Protocol format with proper CBOR tag 42 CID links.
/// DAG-CBOR requires map keys sorted by encoded byte length, then lexicographically.
fn build_signed_commit(
    did: &str,
    data_cid: &cirrus_common::cid::Cid,
    rev: &str,
    prev_cid: Option<&cirrus_common::cid::Cid>,
    signing_key: Option<&cirrus_common::crypto::Keypair>,
) -> Result<(Vec<u8>, cirrus_common::cid::Cid), String> {
    use ciborium::Value as CborValue;

    // Encode a CID as a DAG-CBOR link: CBOR tag 42 wrapping 0x00 + CID bytes
    let cid_link = |cid: &cirrus_common::cid::Cid| -> CborValue {
        let mut cid_bytes = vec![0x00]; // identity multibase prefix
        cid_bytes.extend_from_slice(&cid.to_bytes());
        CborValue::Tag(42, Box::new(CborValue::Bytes(cid_bytes)))
    };

    let prev_value = match prev_cid {
        Some(c) => cid_link(c),
        None => CborValue::Null,
    };

    // Build unsigned commit (keys sorted by encoded byte length, then lexicographic)
    // 3-char keys: "did", "rev" — 4-char keys: "data", "prev" — 7-char key: "version"
    let unsigned = CborValue::Map(vec![
        (CborValue::Text("did".to_string()), CborValue::Text(did.to_string())),
        (CborValue::Text("rev".to_string()), CborValue::Text(rev.to_string())),
        (CborValue::Text("data".to_string()), cid_link(data_cid)),
        (CborValue::Text("prev".to_string()), prev_value.clone()),
        (CborValue::Text("version".to_string()), CborValue::Integer(3.into())),
    ]);

    let mut unsigned_bytes = Vec::new();
    ciborium::into_writer(&unsigned, &mut unsigned_bytes)
        .map_err(|e| format!("failed to encode unsigned commit: {e}"))?;

    // If we have a signing key, sign and include sig; otherwise produce unsigned commit
    let commit_cbor = if let Some(key) = signing_key {
        let sig = key.sign(&unsigned_bytes)
            .map_err(|e| format!("failed to sign commit: {e}"))?;

        // Build signed commit (sig is a 3-char key, sorted between "rev" and "data")
        let signed = CborValue::Map(vec![
            (CborValue::Text("did".to_string()), CborValue::Text(did.to_string())),
            (CborValue::Text("rev".to_string()), CborValue::Text(rev.to_string())),
            (CborValue::Text("sig".to_string()), CborValue::Bytes(sig)),
            (CborValue::Text("data".to_string()), cid_link(data_cid)),
            (CborValue::Text("prev".to_string()), prev_value),
            (CborValue::Text("version".to_string()), CborValue::Integer(3.into())),
        ]);

        let mut signed_bytes = Vec::new();
        ciborium::into_writer(&signed, &mut signed_bytes)
            .map_err(|e| format!("failed to encode signed commit: {e}"))?;
        signed_bytes
    } else {
        unsigned_bytes
    };

    let commit_cid = cirrus_common::cid::Cid::for_cbor(&commit_cbor);
    Ok((commit_cbor, commit_cid))
}

async fn create_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateRecordInput>,
) -> Response {
    // Apply general rate limiting
    if let Some(rate_limits) = &state.rate_limits {
        let ip = client_ip_from_headers(&headers);
        if let Err(e) = crate::rate_limit::check_rate_limit(&rate_limits.general, ip) {
            return e.into_response();
        }
    }

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

    // Validate collection NSID
    if let Err(e) = crate::repo::validate_collection(&input.collection) {
        return e.into_response();
    }

    if input.validate {
        if let Err(e) = state.lexicons.validate_record(&input.collection, &input.record) {
            return e.into_response();
        }
    }

    let rkey = input.rkey.unwrap_or_else(generate_rkey);

    // Validate rkey format
    if let Err(e) = crate::repo::validate_rkey(&rkey) {
        return e.into_response();
    }

    // Enforce max record payload size
    let record_json = serde_json::to_vec(&input.record).unwrap_or_default();
    if record_json.len() > crate::repo::MAX_RECORD_SIZE {
        return PdsError::InvalidRecord(format!(
            "record exceeds max size of {} bytes",
            crate::repo::MAX_RECORD_SIZE
        ))
        .into_response();
    }

    let cbor_bytes = match cirrus_common::cbor::encode(&input.record) {
        Ok(b) => b,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    let record_cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes);
    let cid = record_cid.to_string();

    let block_key = format!("{}:{}", input.collection, rkey);
    let prev_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = state.storage.put_block(&block_key, &cbor_bytes, prev_state.rev.as_deref()) {
        return e.into_response();
    }

    // Build the MST from all records in the repo (including the one we just wrote)
    let all_blocks = match state.storage.get_all_blocks() {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let mut mst_entries: Vec<(String, cirrus_common::cid::Cid)> = all_blocks
        .iter()
        .map(|b| {
            let path = b.cid.replace(':', "/"); // storage uses collection:rkey, MST uses collection/rkey
            let record_cid = cirrus_common::cid::Cid::for_cbor(&b.bytes);
            (path, record_cid)
        })
        .collect();
    mst_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mst_result = crate::mst::build(&mst_entries);

    // Build a signed DAG-CBOR commit pointing to the MST root
    let rev = cirrus_common::Tid::now().to_string();
    let prev_commit_cid = prev_state.root_cid.as_ref().and_then(|s| {
        cirrus_common::cid::Cid::from_string(s).ok()
    });

    let (commit_cbor, commit_cid) = match build_signed_commit(
        &auth.did,
        &mst_result.root,
        &rev,
        prev_commit_cid.as_ref(),
        state.signing_key.as_ref(),
    ) {
        Ok(result) => result,
        Err(e) => return PdsError::InvalidRecord(e).into_response(),
    };

    // Update repo state with the new commit
    let seq = match state.storage.update_repo_state(&commit_cid.to_string(), &rev) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Build CAR with commit, MST nodes, and the new record block
    let mut car_buf = Vec::new();
    if let Ok(mut writer) = cirrus_common::car::CarWriter::new(&mut car_buf, commit_cid.clone()) {
        let _ = writer.write_block(&commit_cid, &commit_cbor);
        for (mst_bytes, mst_cid) in &mst_result.blocks {
            let _ = writer.write_block(mst_cid, mst_bytes);
        }
        let _ = writer.write_block(&record_cid, &cbor_bytes);
        drop(writer);
    }

    // Emit firehose commit event
    let path = format!("{}/{rkey}", input.collection);
    state.firehose.publish(crate::sequencer::FirehoseEvent::Commit(
        crate::sequencer::CommitEvent {
            seq,
            rebase: false,
            too_big: false,
            repo: auth.did.clone(),
            commit: commit_cid.to_string(),
            rev: rev.clone(),
            since: prev_state.rev,
            blocks: car_buf,
            ops: vec![crate::sequencer::RepoOpEvent {
                action: "create".to_string(),
                path,
                cid: Some(cid.clone()),
            }],
            blobs: vec![],
            time: chrono::Utc::now().to_rfc3339(),
        },
    ));

    let uri = make_at_uri(&auth.did, &input.collection, &rkey);

    Json(CreateRecordOutput { uri, cid }).into_response()
}

async fn put_record(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    headers: axum::http::HeaderMap,
    Json(input): Json<PutRecordInput>,
) -> Response {
    // Apply general rate limiting
    if let Some(rate_limits) = &state.rate_limits {
        let ip = client_ip_from_headers(&headers);
        if let Err(e) = crate::rate_limit::check_rate_limit(&rate_limits.general, ip) {
            return e.into_response();
        }
    }

    if input.repo != auth.did {
        return PdsError::NotAuthorized("repo mismatch".into()).into_response();
    }

    // Validate collection and rkey
    if let Err(e) = crate::repo::validate_collection(&input.collection) {
        return e.into_response();
    }
    if let Err(e) = crate::repo::validate_rkey(&input.rkey) {
        return e.into_response();
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
    headers: axum::http::HeaderMap,
    Json(input): Json<crate::xrpc::DeleteRecordInput>,
) -> Response {
    // Apply general rate limiting
    if let Some(rate_limits) = &state.rate_limits {
        let ip = client_ip_from_headers(&headers);
        if let Err(e) = crate::rate_limit::check_rate_limit(&rate_limits.general, ip) {
            return e.into_response();
        }
    }

    if input.repo != auth.did {
        return PdsError::NotAuthorized("repo mismatch".into()).into_response();
    }

    // Validate collection and rkey
    if let Err(e) = crate::repo::validate_collection(&input.collection) {
        return e.into_response();
    }
    if let Err(e) = crate::repo::validate_rkey(&input.rkey) {
        return e.into_response();
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

    match state.blob_store.get_blob(&params.cid) {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        ).into_response(),
        Ok(None) => PdsError::RecordNotFound(format!("blob not found: {}", params.cid)).into_response(),
        Err(e) => e.into_response(),
    }
}

async fn upload_blob(
    State(state): State<Arc<AppState>>,
    RequireAdmin(_auth): RequireAdmin,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");

    match state.blob_store.put_blob(&body, content_type) {
        Ok(blob_ref) => Json(UploadBlobOutput { blob: blob_ref }).into_response(),
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

    let all_blocks = match state.storage.get_all_blocks() {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Build MST from all records
    let mut mst_entries: Vec<(String, cirrus_common::cid::Cid)> = all_blocks
        .iter()
        .map(|b| {
            let path = b.cid.replace(':', "/");
            let record_cid = cirrus_common::cid::Cid::for_cbor(&b.bytes);
            (path, record_cid)
        })
        .collect();
    mst_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mst_result = crate::mst::build(&mst_entries);

    // Build signed commit pointing to MST root
    let rev = repo_state.rev.as_deref().unwrap_or("initial");
    let prev_commit_cid = repo_state.root_cid.as_ref().and_then(|s| {
        cirrus_common::cid::Cid::from_string(s).ok()
    });

    let (commit_cbor, commit_cid) = match build_signed_commit(
        &state.did,
        &mst_result.root,
        rev,
        prev_commit_cid.as_ref(),
        state.signing_key.as_ref(),
    ) {
        Ok(result) => result,
        Err(e) => return PdsError::InvalidRecord(e).into_response(),
    };

    // Write CAR: commit + MST nodes + record blocks
    let mut car_buf = Vec::new();
    let mut writer = match cirrus_common::car::CarWriter::new(&mut car_buf, commit_cid.clone()) {
        Ok(w) => w,
        Err(e) => return PdsError::InvalidRecord(format!("CAR header error: {e}")).into_response(),
    };

    if let Err(e) = writer.write_block(&commit_cid, &commit_cbor) {
        return PdsError::InvalidRecord(format!("CAR commit error: {e}")).into_response();
    }
    for (mst_bytes, mst_cid) in &mst_result.blocks {
        if let Err(e) = writer.write_block(mst_cid, mst_bytes) {
            return PdsError::InvalidRecord(format!("CAR MST error: {e}")).into_response();
        }
    }
    for block in &all_blocks {
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
    // Fast path for the local handle
    if params.handle == state.handle {
        return Json(serde_json::json!({
            "did": state.did
        })).into_response();
    }

    // Resolve non-local handles via DNS TXT / HTTP
    match state.handle_resolver.resolve(&params.handle).await {
        Ok(resolution) => Json(serde_json::json!({
            "did": resolution.did
        })).into_response(),
        Err(e) => e.into_response(),
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
            password_hash: String::new(),
            hostname: "test.local".to_string(),
            did: "did:plc:test".to_string(),
            handle: "test.local".to_string(),
            public_key_multibase: "zQ3shtest".to_string(),
            firehose: Firehose::new(),
            blob_store: Box::new(crate::blobs::MemoryBlobStore::new()),
            handle_resolver: crate::handle::HandleResolver::new(),
            rate_limits: None,
            oauth_storage: None,
            signing_key: None,
        });

        let _router = create_router(state);
    }
}
