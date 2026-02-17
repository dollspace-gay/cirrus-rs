//! XRPC route handlers for AT Protocol PDS.

use std::net::IpAddr;
use std::sync::Arc;

use cirrus_oauth::OAuthStorage as _;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
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
    AppPasswordInfo, ApplyWriteOp, ApplyWriteResult, ApplyWritesCommit, ApplyWritesInput,
    ApplyWritesOutput, CheckAccountStatusOutput, ConfirmEmailInput, CreateAccountInput,
    CreateAccountOutput, CreateAppPasswordInput, CreateAppPasswordOutput, CreateRecordInput,
    CreateRecordOutput, CreateReportInput, CreateSessionInput, DeactivateAccountInput,
    DeleteAccountInput, DescribeRepoOutput, GetPreferencesOutput,
    GetRecommendedDidCredentialsOutput, GetRecordOutput, GetServiceAuthOutput,
    ListAppPasswordsOutput, ListRecordEntry, ListRecordsOutput, PutPreferencesInput,
    PutRecordInput, PutRecordOutput, RequestPasswordResetInput, ResetPasswordInput,
    RevokeAppPasswordInput, SessionOutput, SignPlcOperationInput, SignPlcOperationOutput,
    SubmitPlcOperationInput, UpdateEmailInput, UpdateHandleInput, UploadBlobOutput, XrpcError,
};

/// Application state shared across handlers.
pub struct AppState {
    /// Repository storage.
    pub storage: SqliteStorage,
    /// Lexicon store for validation.
    pub lexicons: LexiconStore,
    /// JWT secret for session tokens.
    pub jwt_secret: Vec<u8>,
    /// Bcrypt hash of the account password (mutable for createAccount).
    pub password_hash: parking_lot::RwLock<String>,
    /// This PDS's hostname.
    pub hostname: String,
    /// DID of the account.
    pub did: String,
    /// Handle of the account (mutable for updateHandle).
    pub handle: parking_lot::RwLock<String>,
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
    /// Crawler/relay notifier (None to disable outbound notifications).
    pub crawlers: Option<crate::crawlers::Crawlers>,
    /// AppView proxy configuration (None to disable pipethrough).
    pub appview: Option<crate::pipethrough::AppViewConfig>,
}

impl AppState {
    /// Returns the current handle (cloned from the `RwLock`).
    #[must_use]
    pub fn handle(&self) -> String {
        self.handle.read().clone()
    }

    /// Returns the current password hash (cloned from the `RwLock`).
    #[must_use]
    pub fn password_hash(&self) -> String {
        self.password_hash.read().clone()
    }
}

/// Creates the XRPC router.
#[must_use = "returns the configured router"]
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Server endpoints
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(create_account),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(create_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(refresh_session),
        )
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route(
            "/xrpc/com.atproto.server.deleteSession",
            post(delete_session),
        )
        .route(
            "/xrpc/com.atproto.server.activateAccount",
            post(activate_account),
        )
        .route(
            "/xrpc/com.atproto.server.deactivateAccount",
            post(deactivate_account),
        )
        .route(
            "/xrpc/com.atproto.server.checkAccountStatus",
            get(check_account_status),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(get_service_auth),
        )
        .route(
            "/xrpc/com.atproto.server.createAppPassword",
            post(create_app_password),
        )
        .route(
            "/xrpc/com.atproto.server.listAppPasswords",
            get(list_app_passwords),
        )
        .route(
            "/xrpc/com.atproto.server.revokeAppPassword",
            post(revoke_app_password),
        )
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
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        // Sync endpoints
        .route("/xrpc/com.atproto.sync.getHead", get(get_head))
        .route(
            "/xrpc/com.atproto.sync.getLatestCommit",
            get(get_latest_commit),
        )
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/xrpc/com.atproto.sync.getRepoStatus", get(get_repo_status))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route(
            "/xrpc/com.atproto.sync.subscribeRepos",
            get(subscribe_repos),
        )
        .route("/xrpc/com.atproto.sync.requestCrawl", post(request_crawl))
        .route(
            "/xrpc/com.atproto.sync.notifyOfUpdate",
            post(notify_of_update),
        )
        // Identity endpoints
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
        .route(
            "/xrpc/com.atproto.identity.updateHandle",
            post(update_handle),
        )
        .route(
            "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
            get(get_recommended_did_credentials),
        )
        .route(
            "/xrpc/com.atproto.identity.requestPlcOperationSignature",
            post(request_plc_operation_signature),
        )
        .route(
            "/xrpc/com.atproto.identity.signPlcOperation",
            post(sign_plc_operation),
        )
        .route(
            "/xrpc/com.atproto.identity.submitPlcOperation",
            post(submit_plc_operation),
        )
        // Email endpoints
        .route(
            "/xrpc/com.atproto.server.requestEmailConfirmation",
            post(request_email_confirmation),
        )
        .route("/xrpc/com.atproto.server.confirmEmail", post(confirm_email))
        .route(
            "/xrpc/com.atproto.server.requestPasswordReset",
            post(request_password_reset),
        )
        .route(
            "/xrpc/com.atproto.server.resetPassword",
            post(reset_password),
        )
        .route(
            "/xrpc/com.atproto.server.requestEmailUpdate",
            post(request_email_update),
        )
        .route("/xrpc/com.atproto.server.updateEmail", post(update_email))
        // Account deletion endpoints
        .route(
            "/xrpc/com.atproto.server.requestAccountDelete",
            post(request_account_delete),
        )
        .route(
            "/xrpc/com.atproto.server.deleteAccount",
            post(delete_account),
        )
        // Moderation endpoints
        .route(
            "/xrpc/com.atproto.moderation.createReport",
            post(create_report),
        )
        // OAuth endpoints
        .route("/oauth/authorize", get(oauth_authorize_get))
        .route("/oauth/authorize", post(oauth_authorize_post))
        .route("/oauth/token", post(oauth_token))
        .route("/oauth/par", post(oauth_par))
        .route("/oauth/revoke", post(oauth_revoke))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_server_metadata),
        )
        // Health check
        .route("/health", get(health_check))
        .route("/.well-known/atproto-did", get(well_known_did))
        .route("/.well-known/did.json", get(well_known_did_json))
        .fallback(pipethrough_fallback)
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
async fn well_known_did_json(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let handle = state.handle();
    let doc = crate::did::create_did_document(
        &state.did,
        &handle,
        &format!("https://{}", state.hostname),
        &state.public_key_multibase,
    );
    Json(serde_json::to_value(doc).unwrap_or_default())
}

async fn describe_server(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "availableUserDomains": [],
        "inviteCodeRequired": false,
        "did": format!("did:web:{}", state.hostname),
        "links": {}
    }))
}

async fn create_account(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(input): Json<CreateAccountInput>,
) -> Response {
    // Apply login rate limiting if enabled
    if let Some(rate_limits) = &state.rate_limits {
        let ip = client_ip_from_headers(&headers);
        if let Err(e) = crate::rate_limit::check_rate_limit(&rate_limits.login, ip) {
            return e.into_response();
        }
    }

    // Check if account already exists (password hash is non-empty)
    if !state.password_hash().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::new(
                "AccountAlreadyExists",
                "Account has already been created",
            )),
        )
            .into_response();
    }

    // Validate handle format
    if let Err(e) = cirrus_common::atproto::Handle::validate(&input.handle) {
        return PdsError::InvalidRecord(format!("invalid handle: {e}")).into_response();
    }

    // Validate password is non-empty
    if input.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::invalid_request("password is required")),
        )
            .into_response();
    }

    // Hash the password
    let hash = match crate::auth::hash_password(&input.password) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };

    // Persist password hash to settings table for durability
    if let Err(e) = state.storage.put_setting("password_hash", &hash) {
        return PdsError::Storage(format!("failed to persist password: {e}")).into_response();
    }

    // Update in-memory password hash
    *state.password_hash.write() = hash;

    // Update handle if different from the pre-configured one
    if input.handle != state.handle() {
        if let Err(e) = state.storage.put_setting("handle", &input.handle) {
            return PdsError::Storage(format!("failed to persist handle: {e}")).into_response();
        }
        *state.handle.write() = input.handle.clone();
    }

    // Mark the account as active
    if let Err(e) = state.storage.set_active(true) {
        return e.into_response();
    }

    // Generate session tokens
    let access_jwt = match crate::auth::create_access_token(&state.did, &state.jwt_secret) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    let (refresh_jwt, token_id) =
        match crate::auth::create_refresh_token(&state.did, &state.jwt_secret) {
            Ok(t) => t,
            Err(e) => return e.into_response(),
        };

    // Persist refresh token
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
    let _ = state.storage.store_refresh_token(
        &token_id,
        &state.did,
        &token_id, // first token is its own family
        None,
        &expires_at,
    );

    Json(CreateAccountOutput {
        access_jwt,
        refresh_jwt,
        handle: state.handle(),
        did: state.did.clone(),
    })
    .into_response()
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

    let handle = state.handle();
    let pw_hash = state.password_hash();
    let config = crate::auth::SessionConfig {
        did: &state.did,
        handle: &handle,
        password_hash: &pw_hash,
        jwt_secret: &state.jwt_secret,
    };

    match crate::auth::create_session(&input.identifier, &input.password, &config) {
        Ok((tokens, token_id)) => {
            // Persist refresh token
            let expires_at = (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
            let _ = state.storage.store_refresh_token(
                &token_id,
                &state.did,
                &token_id,
                None,
                &expires_at,
            );
            Json(SessionOutput {
                access_jwt: tokens.access_jwt,
                refresh_jwt: tokens.refresh_jwt,
                handle: handle.clone(),
                did: state.did.clone(),
            })
            .into_response()
        }
        Err(_) => {
            // Fall back to app passwords if main password fails
            if input.identifier == state.did || input.identifier == handle {
                if let Ok(Some(entry)) = state.storage.verify_app_password(&input.password) {
                    match crate::auth::create_access_token(&state.did, &state.jwt_secret) {
                        Ok(access_jwt) => {
                            match crate::auth::create_refresh_token(&state.did, &state.jwt_secret) {
                                Ok((refresh_jwt, token_id)) => {
                                    let expires_at = (chrono::Utc::now()
                                        + chrono::Duration::days(90))
                                    .to_rfc3339();
                                    let _ = state.storage.store_refresh_token(
                                        &token_id,
                                        &state.did,
                                        &token_id,
                                        Some(&entry.name),
                                        &expires_at,
                                    );
                                    return Json(SessionOutput {
                                        access_jwt,
                                        refresh_jwt,
                                        handle: handle.clone(),
                                        did: state.did.clone(),
                                    })
                                    .into_response();
                                }
                                Err(e) => return e.into_response(),
                            }
                        }
                        Err(e) => return e.into_response(),
                    }
                }
            }
            PdsError::AuthFailed("invalid identifier or password".into()).into_response()
        }
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

    // Extract jti (token ID) from the refresh token for DB lookup
    let token_bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    let jti: Option<String> =
        cirrus_common::jwt::decode_unverified::<cirrus_common::jwt::Claims>(token_bearer)
            .ok()
            .and_then(|claims| claims.jti);

    // If we have a jti, validate against DB
    if let Some(ref token_id) = jti {
        match state.storage.get_refresh_token(token_id) {
            Ok(Some(stored)) => {
                // Check if token was already used (reuse detection)
                if let Some(ref used_at) = stored.used_at {
                    if crate::storage::SqliteStorage::is_within_grace_period(used_at) {
                        // Within grace period — return the successor token
                        // (the client may have retried). Generate fresh tokens.
                    } else {
                        // Reuse detected outside grace period — revoke entire family
                        let _ = state.storage.revoke_token_family(&stored.family_id);
                        return PdsError::AuthFailed("token reuse detected, family revoked".into())
                            .into_response();
                    }
                }

                // Rotate: generate new tokens, mark old as used
                match crate::auth::refresh_tokens(&auth.did, &state.jwt_secret) {
                    Ok((tokens, new_token_id)) => {
                        // Mark old token as used, pointing to new
                        let _ = state.storage.use_refresh_token(token_id, &new_token_id);

                        // Store new token in same family
                        let expires_at =
                            (chrono::Utc::now() + chrono::Duration::days(90)).to_rfc3339();
                        let _ = state.storage.store_refresh_token(
                            &new_token_id,
                            &auth.did,
                            &stored.family_id,
                            stored.app_password_name.as_deref(),
                            &expires_at,
                        );

                        return Json(SessionOutput {
                            access_jwt: tokens.access_jwt,
                            refresh_jwt: tokens.refresh_jwt,
                            handle: state.handle(),
                            did: auth.did,
                        })
                        .into_response();
                    }
                    Err(e) => return e.into_response(),
                }
            }
            Ok(None) => {
                // Token not in DB — may be a legacy token, allow refresh without persistence
            }
            Err(_) => {
                // DB error — fall through to stateless refresh
            }
        }
    }

    // Stateless fallback (no jti or DB miss)
    match crate::auth::refresh_tokens(&auth.did, &state.jwt_secret) {
        Ok((tokens, _new_token_id)) => Json(SessionOutput {
            access_jwt: tokens.access_jwt,
            refresh_jwt: tokens.refresh_jwt,
            handle: state.handle(),
            did: auth.did,
        })
        .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn get_session(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "handle": state.handle(),
        "did": auth.did,
        "active": true
    }))
}

async fn delete_session(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> StatusCode {
    // Revoke all refresh tokens for this user
    let _ = state.storage.revoke_all_refresh_tokens(&auth.did);
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
    })
    .into_response()
}

/// Query parameters for getServiceAuth.
#[derive(Debug, Deserialize)]
pub struct GetServiceAuthParams {
    /// DID of the audience (required).
    pub aud: String,
    /// Requested expiration in seconds from now (optional).
    pub exp: Option<u64>,
    /// Lexicon method this token will be used for (optional).
    pub lxm: Option<String>,
}

/// Maximum token lifetime when lxm is specified (30 minutes).
const SERVICE_AUTH_MAX_EXP_WITH_LXM: u64 = 30 * 60;
/// Maximum token lifetime when lxm is NOT specified (60 seconds).
const SERVICE_AUTH_MAX_EXP_WITHOUT_LXM: u64 = 60;

async fn get_service_auth(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Query(params): Query<GetServiceAuthParams>,
) -> Response {
    // Signing key is required for service auth
    let signing_key = match &state.signing_key {
        Some(key) => key,
        None => return PdsError::AuthFailed("signing key not configured".into()).into_response(),
    };

    // Validate audience is a DID
    if !params.aud.starts_with("did:") {
        return PdsError::InvalidRecord("aud must be a valid DID".into()).into_response();
    }

    // Determine expiration
    let max_exp = if params.lxm.is_some() {
        SERVICE_AUTH_MAX_EXP_WITH_LXM
    } else {
        SERVICE_AUTH_MAX_EXP_WITHOUT_LXM
    };

    let exp_seconds = match params.exp {
        Some(requested) => {
            if requested > max_exp {
                return PdsError::InvalidRecord(format!(
                    "requested expiration too long: max {max_exp}s"
                ))
                .into_response();
            }
            requested
        }
        None => max_exp,
    };

    // Build claims
    let mut claims = cirrus_common::jwt::Claims::new(&state.did, exp_seconds).with_aud(&params.aud);

    if let Some(ref lxm) = params.lxm {
        claims = claims.with_lxm(lxm);
    }

    // Generate a unique JTI
    let jti = format!("{:016x}", rand::random::<u64>());
    claims = claims.with_jti(jti);

    // Sign the token with ES256K
    match cirrus_common::jwt::sign_es256k(&claims, signing_key) {
        Ok(token) => Json(GetServiceAuthOutput { token }).into_response(),
        Err(e) => {
            PdsError::AuthFailed(format!("failed to sign service token: {e}")).into_response()
        }
    }
}

async fn create_app_password(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Json(input): Json<CreateAppPasswordInput>,
) -> Response {
    if input.name.is_empty() || input.name.len() > 100 {
        return PdsError::InvalidRecord("name must be 1-100 characters".into()).into_response();
    }

    let password = crate::auth::generate_app_password();
    let hash = match crate::auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };

    if let Err(e) = state
        .storage
        .create_app_password(&input.name, &hash, input.privileged)
    {
        return PdsError::InvalidRecord(format!("failed to create app password: {e}"))
            .into_response();
    }

    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    Json(CreateAppPasswordOutput {
        name: input.name,
        password,
        privileged: input.privileged,
        created_at,
    })
    .into_response()
}

async fn list_app_passwords(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
) -> Response {
    match state.storage.list_app_passwords() {
        Ok(entries) => {
            let passwords = entries
                .into_iter()
                .map(|e| AppPasswordInfo {
                    name: e.name,
                    privileged: e.privileged,
                    created_at: e.created_at,
                })
                .collect();
            Json(ListAppPasswordsOutput { passwords }).into_response()
        }
        Err(e) => e.into_response(),
    }
}

async fn revoke_app_password(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Json(input): Json<RevokeAppPasswordInput>,
) -> Response {
    match state.storage.delete_app_password(&input.name) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => PdsError::InvalidRecord("app password not found".into()).into_response(),
        Err(e) => e.into_response(),
    }
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
    let handle = state.handle();
    if params.repo != state.did && params.repo != handle {
        return PdsError::RepoNotFound(params.repo).into_response();
    }

    let did_doc = crate::did::create_did_document(
        &state.did,
        &handle,
        &format!("https://{}", state.hostname),
        &state.public_key_multibase,
    );

    let did_doc_value = match serde_json::to_value(&did_doc) {
        Ok(v) => v,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    Json(DescribeRepoOutput {
        handle,
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
    })
    .into_response()
}

async fn get_record(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetRecordParams>,
) -> Response {
    let uri = make_at_uri(&state.did, &params.collection, &params.rkey);

    // Try the record index first for O(1) lookup
    match state
        .storage
        .get_record_index(&params.collection, &params.rkey)
    {
        Ok(Some(idx)) => {
            let block = match state.storage.get_block(&idx.block_cid) {
                Ok(Some(b)) => b,
                Ok(None) => return PdsError::RecordNotFound(uri).into_response(),
                Err(e) => return e.into_response(),
            };
            let value: serde_json::Value = match cirrus_common::cbor::decode(&block) {
                Ok(v) => v,
                Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
            };
            return Json(GetRecordOutput {
                uri,
                cid: idx.record_cid,
                value,
            })
            .into_response();
        }
        Ok(None) => {
            // Fallback to direct block lookup for backwards compatibility
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
        Err(e) => e.into_response(),
    }
}

async fn list_records(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListRecordsParams>,
) -> Response {
    if params.repo != state.did && params.repo != state.handle() {
        return PdsError::RepoNotFound(params.repo).into_response();
    }

    let limit = params.limit.unwrap_or(50).min(100);
    let reverse = params.reverse.unwrap_or(false);

    // Try indexed listing first, fall back to block-based listing
    let indexed_entries = state.storage.list_records_indexed(
        &params.collection,
        limit,
        params.cursor.as_deref(),
        reverse,
    );

    let (rkeys, record_bytes): (Vec<String>, Vec<Vec<u8>>) = match indexed_entries {
        Ok(ref entries) if !entries.is_empty() => entries
            .iter()
            .map(|e| (e.rkey.clone(), e.bytes.clone()))
            .unzip(),
        _ => {
            // Fallback for pre-index records
            let entries = match state.storage.list_records(
                &params.collection,
                limit,
                params.cursor.as_deref(),
                reverse,
            ) {
                Ok(e) => e,
                Err(e) => return e.into_response(),
            };
            entries
                .iter()
                .map(|e| (e.rkey.clone(), e.bytes.clone()))
                .unzip()
        }
    };

    let mut records = Vec::with_capacity(rkeys.len());
    for (rkey, bytes) in rkeys.iter().zip(record_bytes.iter()) {
        let value: serde_json::Value = match cirrus_common::cbor::decode(bytes) {
            Ok(v) => v,
            Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
        };
        let cid = cirrus_common::cid::Cid::for_cbor(bytes).to_string();
        let uri = make_at_uri(&state.did, &params.collection, rkey);
        records.push(ListRecordEntry { uri, cid, value });
    }

    let cursor = if records.len() == limit as usize {
        rkeys.last().cloned()
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
        (
            CborValue::Text("did".to_string()),
            CborValue::Text(did.to_string()),
        ),
        (
            CborValue::Text("rev".to_string()),
            CborValue::Text(rev.to_string()),
        ),
        (CborValue::Text("data".to_string()), cid_link(data_cid)),
        (CborValue::Text("prev".to_string()), prev_value.clone()),
        (
            CborValue::Text("version".to_string()),
            CborValue::Integer(3.into()),
        ),
    ]);

    let mut unsigned_bytes = Vec::new();
    ciborium::into_writer(&unsigned, &mut unsigned_bytes)
        .map_err(|e| format!("failed to encode unsigned commit: {e}"))?;

    // If we have a signing key, sign and include sig; otherwise produce unsigned commit
    let commit_cbor = if let Some(key) = signing_key {
        let sig = key
            .sign(&unsigned_bytes)
            .map_err(|e| format!("failed to sign commit: {e}"))?;

        // Build signed commit (sig is a 3-char key, sorted between "rev" and "data")
        let signed = CborValue::Map(vec![
            (
                CborValue::Text("did".to_string()),
                CborValue::Text(did.to_string()),
            ),
            (
                CborValue::Text("rev".to_string()),
                CborValue::Text(rev.to_string()),
            ),
            (CborValue::Text("sig".to_string()), CborValue::Bytes(sig)),
            (CborValue::Text("data".to_string()), cid_link(data_cid)),
            (CborValue::Text("prev".to_string()), prev_value),
            (
                CborValue::Text("version".to_string()),
                CborValue::Integer(3.into()),
            ),
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

/// Result of an MST rebuild inside a write transaction.
struct MstCommitResult {
    event: crate::sequencer::FirehoseEvent,
    rev: String,
    commit_cid: cirrus_common::cid::Cid,
}

/// Rebuilds the MST from the record index, creates a signed commit, stores MST blocks,
/// updates repo state, builds a CAR file, and persists the firehose event.
///
/// This is the shared write-path used by `create_record`, `put_record`, and `delete_record`.
/// It reads lightweight `(path, record_cid)` pairs from the record index instead of loading
/// all block bytes, making it efficient even for large repos.
fn rebuild_mst_and_commit(
    conn: &rusqlite::Connection,
    did: &str,
    signing_key: Option<&cirrus_common::crypto::Keypair>,
    ops: Vec<crate::sequencer::RepoOpEvent>,
) -> crate::error::Result<MstCommitResult> {
    let prev_state = crate::storage::SqliteStorage::get_repo_state_conn(conn)?;

    // Build MST from lightweight record index entries (no block bytes loaded)
    let record_entries = crate::storage::SqliteStorage::get_all_record_entries_conn(conn)?;
    let mst_entries: Vec<(String, cirrus_common::cid::Cid)> = record_entries
        .into_iter()
        .filter_map(|(path, cid_str)| {
            cirrus_common::cid::Cid::from_string(&cid_str)
                .ok()
                .map(|cid| (path, cid))
        })
        .collect();

    let mst_result = crate::mst::build(&mst_entries);

    // Persist MST blocks for later use by getRepo
    crate::storage::SqliteStorage::store_mst_blocks_conn(conn, &mst_result.blocks)?;

    // Build signed commit
    let rev = cirrus_common::Tid::now().to_string();
    let prev_commit_cid = prev_state
        .root_cid
        .as_ref()
        .and_then(|s| cirrus_common::cid::Cid::from_string(s).ok());

    let (commit_cbor, commit_cid) = build_signed_commit(
        did,
        &mst_result.root,
        &rev,
        prev_commit_cid.as_ref(),
        signing_key,
    )
    .map_err(PdsError::InvalidRecord)?;

    // Update repo state with the new commit CID
    let seq =
        crate::storage::SqliteStorage::update_repo_state_conn(conn, &commit_cid.to_string(), &rev)?;

    // Build CAR with commit + MST nodes + referenced record blocks
    let mut car_buf = Vec::new();
    if let Ok(mut writer) = cirrus_common::car::CarWriter::new(&mut car_buf, commit_cid.clone()) {
        let _ = writer.write_block(&commit_cid, &commit_cbor);
        for (mst_bytes, mst_cid) in &mst_result.blocks {
            let _ = writer.write_block(mst_cid, mst_bytes);
        }
        // Include record blocks referenced by the ops
        for op in &ops {
            if let Some(ref cid_str) = op.cid {
                if let Ok(cid) = cirrus_common::cid::Cid::from_string(cid_str) {
                    // Look up the block by collection:rkey
                    let block_key = op.path.replace('/', ":");
                    let result: std::result::Result<Vec<u8>, _> = conn
                        .prepare("SELECT bytes FROM blocks WHERE cid = ?")
                        .and_then(|mut stmt| {
                            stmt.query_row(rusqlite::params![&block_key], |row| row.get(0))
                        });
                    if let Ok(bytes) = result {
                        let _ = writer.write_block(&cid, &bytes);
                    }
                }
            }
        }
        drop(writer);
    }

    // Persist firehose event inside the transaction
    let event = crate::sequencer::FirehoseEvent::Commit(crate::sequencer::CommitEvent {
        seq,
        rebase: false,
        too_big: false,
        repo: did.to_string(),
        commit: commit_cid.to_string(),
        rev: rev.clone(),
        since: prev_state.rev,
        blocks: car_buf,
        ops,
        blobs: vec![],
        time: chrono::Utc::now().to_rfc3339(),
    });

    if let Ok(payload) = event.encode() {
        let _ = crate::storage::SqliteStorage::persist_event_conn(conn, "commit", &payload);
    }

    Ok(MstCommitResult {
        event,
        rev,
        commit_cid,
    })
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
        if let Err(e) = state
            .lexicons
            .validate_record(&input.collection, &input.record)
        {
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

    // Perform the entire write atomically: put block, index, rebuild MST, commit, persist event
    let did = auth.did.clone();
    let collection = input.collection.clone();
    let signing_key = state.signing_key.clone();
    let rkey_clone = rkey.clone();

    // Extract blob CIDs from the record for reference tracking
    let blob_cids = crate::blobs::extract_blob_cids(&input.record);

    let tx_result = state.storage.write_transaction(|conn| {
        let prev_state = crate::storage::SqliteStorage::get_repo_state_conn(conn)?;

        crate::storage::SqliteStorage::put_block_conn(
            conn,
            &block_key,
            &cbor_bytes,
            prev_state.rev.as_deref(),
        )?;

        // Index the record for efficient queries
        crate::storage::SqliteStorage::index_record_conn(
            conn,
            &collection,
            &rkey_clone,
            &block_key,
            &cid,
        )?;

        // Track blob references
        let record_uri = crate::repo::make_at_uri(&did, &collection, &rkey_clone);
        for blob_cid in &blob_cids {
            crate::storage::SqliteStorage::associate_blob_conn(conn, &record_uri, blob_cid)?;
        }

        // Rebuild MST from record index, sign commit, persist event
        let path = format!("{collection}/{rkey_clone}");
        let ops = vec![crate::sequencer::RepoOpEvent {
            action: "create".to_string(),
            path,
            cid: Some(cid.clone()),
        }];

        rebuild_mst_and_commit(conn, &did, signing_key.as_ref(), ops)
    });

    let result = match tx_result {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };

    // Broadcast to live subscribers (outside transaction)
    state.firehose.publish_event(result.event);
    if let Some(ref crawlers) = state.crawlers {
        crawlers.notify_of_update().await;
    }

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

    if input.validate {
        if let Err(e) = state
            .lexicons
            .validate_record(&input.collection, &input.record)
        {
            return e.into_response();
        }
    }

    let cbor_bytes = match cirrus_common::cbor::encode(&input.record) {
        Ok(b) => b,
        Err(e) => return PdsError::InvalidRecord(e.to_string()).into_response(),
    };

    let cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes).to_string();
    let block_key = format!("{}:{}", input.collection, input.rkey);
    let swap_record = input.swap_record.clone();
    let did = auth.did.clone();
    let signing_key = state.signing_key.clone();

    // Extract blob CIDs from the new record
    let new_blob_cids = crate::blobs::extract_blob_cids(&input.record);
    let record_uri = make_at_uri(&auth.did, &input.collection, &input.rkey);

    let tx_result = state.storage.write_transaction(|conn| {
        // Check swap_record if provided (optimistic concurrency)
        if let Some(ref expected_cid) = swap_record {
            let result: std::result::Result<Vec<u8>, _> = conn
                .prepare("SELECT bytes FROM blocks WHERE cid = ?")
                .and_then(|mut stmt| {
                    stmt.query_row(rusqlite::params![&block_key], |row| row.get(0))
                });
            match result {
                Ok(existing) => {
                    let current_cid = cirrus_common::cid::Cid::for_cbor(&existing).to_string();
                    if &current_cid != expected_cid {
                        return Err(PdsError::InvalidRecord("swap_record CID mismatch".into()));
                    }
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(PdsError::RecordNotFound(block_key.clone()));
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Disassociate old blob references and find unreferenced blobs
        let old_blob_cids =
            crate::storage::SqliteStorage::disassociate_record_blobs_conn(conn, &record_uri)?;

        let repo_state = crate::storage::SqliteStorage::get_repo_state_conn(conn)?;
        crate::storage::SqliteStorage::put_block_conn(
            conn,
            &block_key,
            &cbor_bytes,
            repo_state.rev.as_deref(),
        )?;
        crate::storage::SqliteStorage::index_record_conn(
            conn,
            &input.collection,
            &input.rkey,
            &block_key,
            &cid,
        )?;

        // Associate new blob references
        for blob_cid in &new_blob_cids {
            crate::storage::SqliteStorage::associate_blob_conn(conn, &record_uri, blob_cid)?;
        }

        // Find blobs that lost all references and clean up metadata
        let unreferenced =
            crate::storage::SqliteStorage::find_unreferenced_blobs_conn(conn, &old_blob_cids)?;
        crate::storage::SqliteStorage::delete_blob_metadata_conn(conn, &unreferenced)?;

        // Rebuild MST from record index, sign commit, persist event
        let path = format!("{}/{}", input.collection, input.rkey);
        let ops = vec![crate::sequencer::RepoOpEvent {
            action: "update".to_string(),
            path,
            cid: Some(cid.clone()),
        }];

        let commit = rebuild_mst_and_commit(conn, &did, signing_key.as_ref(), ops)?;

        // Return unreferenced CIDs for blob store cleanup
        Ok((commit, unreferenced))
    });

    let (result, blobs_to_delete) = match tx_result {
        Ok((r, b)) => (r, b),
        Err(e) => return e.into_response(),
    };

    // Broadcast to live subscribers (outside transaction)
    state.firehose.publish_event(result.event);
    if let Some(ref crawlers) = state.crawlers {
        crawlers.notify_of_update().await;
    }

    // Delete unreferenced blobs from blob store (best-effort)
    for blob_cid in &blobs_to_delete {
        let _ = state.blob_store.delete_blob(blob_cid);
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
    let swap_record = input.swap_record.clone();
    let did = auth.did.clone();
    let signing_key = state.signing_key.clone();
    let record_uri = make_at_uri(&auth.did, &input.collection, &input.rkey);

    let tx_result = state.storage.write_transaction(|conn| {
        // Check swap_record if provided
        if let Some(ref expected_cid) = swap_record {
            let result: std::result::Result<Vec<u8>, _> = conn
                .prepare("SELECT bytes FROM blocks WHERE cid = ?")
                .and_then(|mut stmt| {
                    stmt.query_row(rusqlite::params![&block_key], |row| row.get(0))
                });
            match result {
                Ok(existing) => {
                    let current_cid = cirrus_common::cid::Cid::for_cbor(&existing).to_string();
                    if &current_cid != expected_cid {
                        return Err(PdsError::InvalidRecord("swap_record CID mismatch".into()));
                    }
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Err(PdsError::RecordNotFound(block_key.clone()));
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Disassociate blob references before deleting
        let old_blob_cids =
            crate::storage::SqliteStorage::disassociate_record_blobs_conn(conn, &record_uri)?;

        let deleted = crate::storage::SqliteStorage::delete_block_conn(conn, &block_key)?;
        if !deleted {
            return Err(PdsError::RecordNotFound(block_key.clone()));
        }
        crate::storage::SqliteStorage::deindex_record_conn(conn, &input.collection, &input.rkey)?;

        // Find and clean up unreferenced blobs
        let unreferenced =
            crate::storage::SqliteStorage::find_unreferenced_blobs_conn(conn, &old_blob_cids)?;
        crate::storage::SqliteStorage::delete_blob_metadata_conn(conn, &unreferenced)?;

        // Rebuild MST from record index (now without the deleted record), sign commit, persist event
        let path = format!("{}/{}", input.collection, input.rkey);
        let ops = vec![crate::sequencer::RepoOpEvent {
            action: "delete".to_string(),
            path,
            cid: None,
        }];

        let commit = rebuild_mst_and_commit(conn, &did, signing_key.as_ref(), ops)?;
        Ok((commit, unreferenced))
    });

    match tx_result {
        Ok((result, blobs_to_delete)) => {
            // Broadcast to live subscribers (outside transaction)
            state.firehose.publish_event(result.event);
            if let Some(ref crawlers) = state.crawlers {
                crawlers.notify_of_update().await;
            }
            // Delete unreferenced blobs from blob store (best-effort)
            for blob_cid in &blobs_to_delete {
                let _ = state.blob_store.delete_blob(blob_cid);
            }
            StatusCode::OK.into_response()
        }
        Err(e) => e.into_response(),
    }
}

async fn apply_writes(
    State(state): State<Arc<AppState>>,
    RequireAdmin(auth): RequireAdmin,
    headers: axum::http::HeaderMap,
    Json(input): Json<ApplyWritesInput>,
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

    if input.writes.len() > crate::xrpc::MAX_APPLY_WRITES {
        return PdsError::InvalidRecord(format!(
            "too many writes: {} exceeds max of {}",
            input.writes.len(),
            crate::xrpc::MAX_APPLY_WRITES,
        ))
        .into_response();
    }

    let is_active = match state.storage.is_active() {
        Ok(a) => a,
        Err(e) => return e.into_response(),
    };
    if !is_active {
        return PdsError::AccountDeactivated.into_response();
    }

    // Validate all operations upfront before starting the transaction
    for op in &input.writes {
        match op {
            ApplyWriteOp::Create {
                collection,
                rkey,
                value,
            } => {
                if let Err(e) = crate::repo::validate_collection(collection) {
                    return e.into_response();
                }
                if let Some(rkey) = rkey {
                    if let Err(e) = crate::repo::validate_rkey(rkey) {
                        return e.into_response();
                    }
                }
                if input.validate {
                    if let Err(e) = state.lexicons.validate_record(collection, value) {
                        return e.into_response();
                    }
                }
                let record_json = serde_json::to_vec(value).unwrap_or_default();
                if record_json.len() > crate::repo::MAX_RECORD_SIZE {
                    return PdsError::InvalidRecord(format!(
                        "record exceeds max size of {} bytes",
                        crate::repo::MAX_RECORD_SIZE
                    ))
                    .into_response();
                }
            }
            ApplyWriteOp::Update {
                collection,
                rkey,
                value,
            } => {
                if let Err(e) = crate::repo::validate_collection(collection) {
                    return e.into_response();
                }
                if let Err(e) = crate::repo::validate_rkey(rkey) {
                    return e.into_response();
                }
                if input.validate {
                    if let Err(e) = state.lexicons.validate_record(collection, value) {
                        return e.into_response();
                    }
                }
            }
            ApplyWriteOp::Delete { collection, rkey } => {
                if let Err(e) = crate::repo::validate_collection(collection) {
                    return e.into_response();
                }
                if let Err(e) = crate::repo::validate_rkey(rkey) {
                    return e.into_response();
                }
            }
        }
    }

    let did = auth.did.clone();
    let signing_key = state.signing_key.clone();

    // Execute all writes in a single atomic transaction
    let tx_result = state.storage.write_transaction(|conn| {
        let prev_state = crate::storage::SqliteStorage::get_repo_state_conn(conn)?;

        // Check swapCommit for optimistic concurrency
        if let Some(ref expected_commit) = input.swap_commit {
            let current_commit = prev_state.root_cid.as_deref().unwrap_or("");
            if current_commit != expected_commit {
                return Err(PdsError::InvalidSwap(format!(
                    "swapCommit mismatch: expected {expected_commit}, got {current_commit}"
                )));
            }
        }

        let mut results = Vec::with_capacity(input.writes.len());
        let mut ops = Vec::with_capacity(input.writes.len());
        let mut all_dereferenced_cids = Vec::new();

        for op in &input.writes {
            match op {
                ApplyWriteOp::Create {
                    collection,
                    rkey,
                    value,
                } => {
                    let rkey = rkey.clone().unwrap_or_else(generate_rkey);
                    let cbor_bytes = cirrus_common::cbor::encode(value)
                        .map_err(|e| PdsError::InvalidRecord(e.to_string()))?;
                    let record_cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes);
                    let cid = record_cid.to_string();
                    let block_key = format!("{collection}:{rkey}");

                    crate::storage::SqliteStorage::put_block_conn(
                        conn,
                        &block_key,
                        &cbor_bytes,
                        prev_state.rev.as_deref(),
                    )?;
                    crate::storage::SqliteStorage::index_record_conn(
                        conn, collection, &rkey, &block_key, &cid,
                    )?;

                    // Track blob references
                    let uri = make_at_uri(&did, collection, &rkey);
                    for blob_cid in crate::blobs::extract_blob_cids(value) {
                        crate::storage::SqliteStorage::associate_blob_conn(conn, &uri, &blob_cid)?;
                    }

                    let path = format!("{collection}/{rkey}");
                    ops.push(crate::sequencer::RepoOpEvent {
                        action: "create".to_string(),
                        path: path.clone(),
                        cid: Some(cid.clone()),
                    });

                    results.push(ApplyWriteResult::CreateResult { uri, cid });
                }
                ApplyWriteOp::Update {
                    collection,
                    rkey,
                    value,
                } => {
                    let cbor_bytes = cirrus_common::cbor::encode(value)
                        .map_err(|e| PdsError::InvalidRecord(e.to_string()))?;
                    let record_cid = cirrus_common::cid::Cid::for_cbor(&cbor_bytes);
                    let cid = record_cid.to_string();
                    let block_key = format!("{collection}:{rkey}");

                    // Disassociate old blob references
                    let uri = make_at_uri(&did, collection, rkey);
                    let old_cids =
                        crate::storage::SqliteStorage::disassociate_record_blobs_conn(conn, &uri)?;
                    all_dereferenced_cids.extend(old_cids);

                    crate::storage::SqliteStorage::put_block_conn(
                        conn,
                        &block_key,
                        &cbor_bytes,
                        prev_state.rev.as_deref(),
                    )?;
                    crate::storage::SqliteStorage::index_record_conn(
                        conn, collection, rkey, &block_key, &cid,
                    )?;

                    // Associate new blob references
                    for blob_cid in crate::blobs::extract_blob_cids(value) {
                        crate::storage::SqliteStorage::associate_blob_conn(conn, &uri, &blob_cid)?;
                    }

                    let path = format!("{collection}/{rkey}");
                    ops.push(crate::sequencer::RepoOpEvent {
                        action: "update".to_string(),
                        path,
                        cid: Some(cid.clone()),
                    });

                    results.push(ApplyWriteResult::UpdateResult { uri, cid });
                }
                ApplyWriteOp::Delete { collection, rkey } => {
                    let block_key = format!("{collection}:{rkey}");

                    // Disassociate blob references
                    let uri = make_at_uri(&did, collection, rkey);
                    let old_cids =
                        crate::storage::SqliteStorage::disassociate_record_blobs_conn(conn, &uri)?;
                    all_dereferenced_cids.extend(old_cids);

                    let deleted =
                        crate::storage::SqliteStorage::delete_block_conn(conn, &block_key)?;
                    if !deleted {
                        return Err(PdsError::RecordNotFound(block_key));
                    }
                    crate::storage::SqliteStorage::deindex_record_conn(conn, collection, rkey)?;

                    let path = format!("{collection}/{rkey}");
                    ops.push(crate::sequencer::RepoOpEvent {
                        action: "delete".to_string(),
                        path,
                        cid: None,
                    });

                    results.push(ApplyWriteResult::DeleteResult {});
                }
            }
        }

        // Clean up unreferenced blobs
        let unreferenced = crate::storage::SqliteStorage::find_unreferenced_blobs_conn(
            conn,
            &all_dereferenced_cids,
        )?;
        crate::storage::SqliteStorage::delete_blob_metadata_conn(conn, &unreferenced)?;

        // Single MST rebuild + commit for the entire batch
        let mst_result = rebuild_mst_and_commit(conn, &did, signing_key.as_ref(), ops)?;

        Ok((mst_result, results, unreferenced))
    });

    let (mst_result, results, blobs_to_delete) = match tx_result {
        Ok((m, r, b)) => (m, r, b),
        Err(e) => return e.into_response(),
    };

    // Broadcast to live subscribers (outside transaction)
    state.firehose.publish_event(mst_result.event);
    if let Some(ref crawlers) = state.crawlers {
        crawlers.notify_of_update().await;
    }

    // Delete unreferenced blobs from blob store (best-effort)
    for blob_cid in &blobs_to_delete {
        let _ = state.blob_store.delete_blob(blob_cid);
    }

    Json(ApplyWritesOutput {
        commit: ApplyWritesCommit {
            cid: mst_result.commit_cid.to_string(),
            rev: mst_result.rev,
        },
        results,
    })
    .into_response()
}

async fn get_head(State(state): State<Arc<AppState>>) -> Response {
    match state.storage.get_repo_state() {
        Ok(repo_state) => Json(serde_json::json!({
            "root": repo_state.root_cid
        }))
        .into_response(),
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
        }))
        .into_response(),
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
        )
            .into_response(),
        Ok(None) => {
            PdsError::RecordNotFound(format!("blob not found: {}", params.cid)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Query parameters for getBlocks.
#[derive(Debug, Deserialize)]
struct GetBlocksParams {
    /// Repository DID.
    did: String,
    /// CIDs of blocks to fetch.
    cids: String,
}

async fn get_blocks(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetBlocksParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    // Parse comma-separated CIDs
    let cid_list: Vec<&str> = params
        .cids
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if cid_list.is_empty() {
        return PdsError::InvalidRecord("no CIDs provided".into()).into_response();
    }

    // Fetch blocks and build a CAR
    let mut blocks = Vec::new();
    let mut first_cid = None;

    for cid_str in &cid_list {
        match state.storage.get_block_by_content_cid(cid_str) {
            Ok(Some(data)) => {
                let cid = match cirrus_common::cid::Cid::from_string(cid_str) {
                    Ok(c) => c,
                    Err(e) => {
                        return PdsError::InvalidRecord(format!("invalid CID {cid_str}: {e}"))
                            .into_response()
                    }
                };
                if first_cid.is_none() {
                    first_cid = Some(cid.clone());
                }
                blocks.push((cid, data));
            }
            Ok(None) => {
                return PdsError::RecordNotFound(format!("block not found: {cid_str}"))
                    .into_response();
            }
            Err(e) => return e.into_response(),
        }
    }

    let root = match first_cid {
        Some(cid) => cid,
        None => return PdsError::InvalidRecord("no blocks found".into()).into_response(),
    };

    let mut car_bytes = Vec::new();
    let mut writer = match cirrus_common::car::CarWriter::new(&mut car_bytes, root) {
        Ok(w) => w,
        Err(e) => return PdsError::Storage(e.to_string()).into_response(),
    };

    for (cid, data) in &blocks {
        if let Err(e) = writer.write_block(cid, data) {
            return PdsError::Storage(e.to_string()).into_response();
        }
    }
    drop(writer);

    (
        StatusCode::OK,
        [("content-type", "application/vnd.ipld.car")],
        car_bytes,
    )
        .into_response()
}

/// Query parameters for getRepoStatus.
#[derive(Debug, Deserialize)]
struct GetRepoStatusParams {
    /// Repository DID.
    did: String,
}

async fn get_repo_status(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetRepoStatusParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    match state.storage.get_repo_state() {
        Ok(repo_state) => {
            let mut response = serde_json::json!({
                "did": state.did,
                "active": repo_state.active,
            });

            if repo_state.active {
                if let Some(ref rev) = repo_state.rev {
                    response["rev"] = serde_json::json!(rev);
                }
            } else {
                response["status"] = serde_json::json!("deactivated");
            }

            Json(response).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Query parameters for listRepos.
#[derive(Debug, Deserialize)]
struct ListReposParams {
    /// Max results (default 500).
    #[serde(default = "default_500")]
    limit: u32,
    /// Pagination cursor.
    cursor: Option<String>,
}

const fn default_500() -> u32 {
    500
}

/// Single-user PDS: returns just this repo.
async fn list_repos(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListReposParams>,
) -> Response {
    // If cursor is set, we've already returned the only repo
    if params.cursor.is_some() {
        return Json(serde_json::json!({ "repos": [] })).into_response();
    }

    let _ = params.limit; // acknowledged but single-user always returns 0 or 1

    match state.storage.get_repo_state() {
        Ok(repo_state) => {
            let mut repo = serde_json::json!({
                "did": state.did,
                "active": repo_state.active,
            });

            if let Some(ref root_cid) = repo_state.root_cid {
                repo["head"] = serde_json::json!(root_cid);
            }
            if let Some(ref rev) = repo_state.rev {
                repo["rev"] = serde_json::json!(rev);
            }
            if !repo_state.active {
                repo["status"] = serde_json::json!("deactivated");
            }

            Json(serde_json::json!({ "repos": [repo] })).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Query parameters for listBlobs.
#[derive(Debug, Deserialize)]
struct ListBlobsParams {
    /// Repository DID.
    did: String,
    /// Optional revision cursor (not yet implemented).
    #[allow(dead_code)]
    since: Option<String>,
    /// Max results (default 500).
    #[serde(default = "default_500")]
    limit: u32,
    /// Pagination cursor.
    cursor: Option<String>,
}

async fn list_blobs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListBlobsParams>,
) -> Response {
    if params.did != state.did {
        return PdsError::RepoNotFound(params.did).into_response();
    }

    let limit = params.limit.min(1000);

    match state
        .storage
        .list_blob_cids(params.cursor.as_deref(), limit)
    {
        Ok(cids) => {
            let next_cursor = if cids.len() == limit as usize {
                cids.last().cloned()
            } else {
                None
            };

            Json(serde_json::json!({
                "cids": cids,
                "cursor": next_cursor,
            }))
            .into_response()
        }
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

    let blob_size = body.len();
    match state.blob_store.put_blob(&body, content_type) {
        Ok(blob_ref) => {
            // Track blob metadata for listBlobs
            let _ = state.storage.store_blob_metadata(
                &blob_ref.reference.link,
                blob_size,
                content_type,
            );
            Json(UploadBlobOutput { blob: blob_ref }).into_response()
        }
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

    let repo_state = match state.storage.get_repo_state() {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };

    // Load stored MST blocks (persisted during write operations)
    let mst_blocks = match state.storage.get_all_mst_blocks() {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    // If no stored MST blocks exist (e.g. legacy data), rebuild from record index
    let (mst_block_data, mst_root) = if mst_blocks.is_empty() {
        let all_blocks = match state.storage.get_all_blocks() {
            Ok(b) => b,
            Err(e) => return e.into_response(),
        };
        let mut mst_entries: Vec<(String, cirrus_common::cid::Cid)> = all_blocks
            .iter()
            .map(|b| {
                let path = b.cid.replace(':', "/");
                let record_cid = cirrus_common::cid::Cid::for_cbor(&b.bytes);
                (path, record_cid)
            })
            .collect();
        mst_entries.sort_by(|a, b| a.0.cmp(&b.0));
        let result = crate::mst::build(&mst_entries);
        (result.blocks, result.root)
    } else {
        // Last stored block is the root (build() appends root last)
        let root_cid = cirrus_common::cid::Cid::from_string(
            &mst_blocks.last().map(|b| b.cid.clone()).unwrap_or_default(),
        )
        .unwrap_or_else(|_| cirrus_common::cid::Cid::for_cbor(b""));
        let blocks: Vec<(Vec<u8>, cirrus_common::cid::Cid)> = mst_blocks
            .into_iter()
            .filter_map(|b| {
                cirrus_common::cid::Cid::from_string(&b.cid)
                    .ok()
                    .map(|cid| (b.bytes, cid))
            })
            .collect();
        (blocks, root_cid)
    };

    // Build signed commit pointing to MST root
    let rev = repo_state.rev.as_deref().unwrap_or("initial");
    let prev_commit_cid = repo_state
        .root_cid
        .as_ref()
        .and_then(|s| cirrus_common::cid::Cid::from_string(s).ok());

    let (commit_cbor, commit_cid) = match build_signed_commit(
        &state.did,
        &mst_root,
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
    for (mst_bytes, mst_cid) in &mst_block_data {
        if let Err(e) = writer.write_block(mst_cid, mst_bytes) {
            return PdsError::InvalidRecord(format!("CAR MST error: {e}")).into_response();
        }
    }

    // Write record blocks
    let all_blocks = match state.storage.get_all_blocks() {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
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
    )
        .into_response()
}

/// Query parameters for subscribeRepos.
#[derive(Debug, Deserialize)]
pub struct SubscribeReposParams {
    /// Cursor (sequence number) to resume from. Events after this seq are replayed.
    pub cursor: Option<i64>,
}

async fn subscribe_repos(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SubscribeReposParams>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(move |socket| handle_firehose(socket, state, params.cursor))
}

/// Maximum number of events to replay per batch from the database.
const BACKFILL_BATCH_SIZE: u32 = 500;

async fn handle_firehose(socket: WebSocket, state: Arc<AppState>, cursor: Option<i64>) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to live events BEFORE backfill so we don't miss anything during replay
    let mut rx = state.firehose.subscribe();

    // Use a channel to signal when receiver closes
    let (close_tx, mut close_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn task to handle incoming messages
    tokio::spawn(async move {
        while let Some(msg) = receiver.next().await {
            match msg {
                Ok(Message::Close(_)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        let _ = close_tx.send(());
    });

    // Phase 1: Backfill from database if cursor is provided
    let mut last_backfill_seq: Option<i64> = None;
    if let Some(cursor_seq) = cursor {
        let mut current_cursor = cursor_seq;
        loop {
            let events = match state
                .storage
                .get_events_after(current_cursor, BACKFILL_BATCH_SIZE)
            {
                Ok(e) => e,
                Err(_) => break,
            };

            if events.is_empty() {
                break;
            }

            for event in &events {
                if sender
                    .send(Message::Binary(event.payload.clone().into()))
                    .await
                    .is_err()
                {
                    return; // Client disconnected
                }
                current_cursor = event.seq;
            }

            last_backfill_seq = Some(current_cursor);

            if events.len() < BACKFILL_BATCH_SIZE as usize {
                break; // No more events
            }
        }
    }

    // Phase 2: Stream live events, deduplicating with backfill
    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        // Deduplicate: skip events we already sent during backfill
                        if let Some(backfill_seq) = last_backfill_seq {
                            if event.seq() <= backfill_seq {
                                continue;
                            }
                            // Past the overlap zone, stop checking
                            last_backfill_seq = None;
                        }

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

/// Input for requestCrawl / notifyOfUpdate endpoints.
#[derive(Debug, Deserialize)]
struct CrawlInput {
    /// Hostname of the requesting service.
    #[allow(dead_code)]
    hostname: String,
}

/// Incoming requestCrawl — a relay or other service asks us to crawl them.
/// For a single-user PDS this is a no-op; we just acknowledge the request.
async fn request_crawl(Json(_input): Json<CrawlInput>) -> Response {
    StatusCode::OK.into_response()
}

/// Incoming notifyOfUpdate (deprecated, same as requestCrawl).
async fn notify_of_update(Json(_input): Json<CrawlInput>) -> Response {
    StatusCode::OK.into_response()
}

async fn resolve_handle(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ResolveHandleParams>,
) -> Response {
    // Fast path for the local handle
    if params.handle == state.handle() {
        return Json(serde_json::json!({
            "did": state.did
        }))
        .into_response();
    }

    // Resolve non-local handles via DNS TXT / HTTP
    match state.handle_resolver.resolve(&params.handle).await {
        Ok(resolution) => Json(serde_json::json!({
            "did": resolution.did
        }))
        .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn update_handle(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Json(input): Json<UpdateHandleInput>,
) -> Response {
    // Validate handle format
    if let Err(e) = cirrus_common::atproto::Handle::validate(&input.handle) {
        return PdsError::InvalidRecord(format!("invalid handle: {e}")).into_response();
    }

    let old_handle = state.handle();
    if input.handle == old_handle {
        // No change needed
        return StatusCode::OK.into_response();
    }

    // Persist the new handle to the database
    if let Err(e) = state.storage.put_setting("handle", &input.handle) {
        return PdsError::InvalidRecord(format!("failed to persist handle: {e}")).into_response();
    }

    // Update the in-memory handle
    *state.handle.write() = input.handle.clone();

    // Persist an identity event so firehose subscribers learn about the change
    let identity_payload = serde_json::to_vec(&serde_json::json!({
        "did": state.did,
        "handle": input.handle,
    }))
    .unwrap_or_default();
    let _ = state.storage.persist_event("identity", &identity_payload);

    StatusCode::OK.into_response()
}

// ============================================================================
// PLC operation endpoints
// ============================================================================

/// Returns recommended DID credentials for account migration.
async fn get_recommended_did_credentials(State(state): State<Arc<AppState>>) -> Response {
    let handle = state.handle();
    let pds_endpoint = format!("https://{}", state.hostname);

    let mut verification_methods = serde_json::Map::new();
    verification_methods.insert(
        "atproto".to_string(),
        serde_json::json!(state.public_key_multibase),
    );

    let mut services = serde_json::Map::new();
    services.insert(
        "atproto_pds".to_string(),
        serde_json::json!({
            "type": "AtprotoPersonalDataServer",
            "endpoint": pds_endpoint,
        }),
    );

    // Rotation keys: include the PDS signing key if available
    let rotation_keys = state
        .signing_key
        .as_ref()
        .map(|key| vec![key.public_key_multibase()]);

    Json(GetRecommendedDidCredentialsOutput {
        rotation_keys,
        also_known_as: Some(vec![format!("at://{handle}")]),
        verification_methods: Some(serde_json::Value::Object(verification_methods)),
        services: Some(serde_json::Value::Object(services)),
    })
    .into_response()
}

/// Requests a signature for a PLC operation.
///
/// In a full implementation this sends an email with a confirmation code.
/// For now (single-user PDS without email), it generates and stores a token.
async fn request_plc_operation_signature(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
) -> Response {
    // Generate a random token
    let token = cirrus_oauth::tokens::generate_auth_code();

    // Store token with 10-minute expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = now + 600;

    let token_data = serde_json::json!({
        "token": token,
        "did": state.did,
        "expires_at": expires_at,
    });

    if let Err(e) = state.storage.put_setting(
        "plc_operation_token",
        &serde_json::to_string(&token_data).unwrap_or_default(),
    ) {
        return PdsError::Storage(format!("failed to store token: {e}")).into_response();
    }

    // In production, this would send the token via email.
    // For single-user PDS, the token is retrievable from the settings table.
    StatusCode::OK.into_response()
}

/// Signs a PLC operation with the PDS signing key.
async fn sign_plc_operation(
    State(state): State<Arc<AppState>>,
    RequireAuth(_auth): RequireAuth,
    Json(input): Json<SignPlcOperationInput>,
) -> Response {
    // Validate the token if provided
    if let Some(ref token) = input.token {
        let stored = match state.storage.get_setting("plc_operation_token") {
            Ok(Some(s)) => s,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::new(
                        "ExpiredToken",
                        "No pending PLC operation token",
                    )),
                )
                    .into_response();
            }
            Err(e) => return PdsError::Storage(e.to_string()).into_response(),
        };

        let stored_data: serde_json::Value = match serde_json::from_str(&stored) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::new("ExpiredToken", "Invalid stored token")),
                )
                    .into_response();
            }
        };

        let expected_token = stored_data["token"].as_str().unwrap_or_default();
        let expires_at = stored_data["expires_at"].as_u64().unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if token != expected_token {
            return (
                StatusCode::BAD_REQUEST,
                Json(XrpcError::new("InvalidToken", "Token does not match")),
            )
                .into_response();
        }
        if now > expires_at {
            return (
                StatusCode::BAD_REQUEST,
                Json(XrpcError::new("ExpiredToken", "Token has expired")),
            )
                .into_response();
        }

        // Consume the token
        let _ = state.storage.put_setting("plc_operation_token", "");
    }

    let signing_key = match &state.signing_key {
        Some(key) => key,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(XrpcError::new(
                    "InternalError",
                    "Signing key not configured",
                )),
            )
                .into_response();
        }
    };

    let handle = state.handle();
    let pds_endpoint = format!("https://{}", state.hostname);

    // Build the PLC operation using provided overrides or defaults
    let also_known_as = input
        .also_known_as
        .unwrap_or_else(|| vec![format!("at://{handle}")]);

    let verification_methods = input.verification_methods.unwrap_or_else(|| {
        serde_json::json!({
            "atproto": state.public_key_multibase,
        })
    });

    let services = input.services.unwrap_or_else(|| {
        serde_json::json!({
            "atproto_pds": {
                "type": "AtprotoPersonalDataServer",
                "endpoint": pds_endpoint,
            }
        })
    });

    let rotation_keys = input
        .rotation_keys
        .unwrap_or_else(|| vec![signing_key.public_key_multibase()]);

    // Construct the unsigned PLC operation
    let mut operation = serde_json::json!({
        "type": "plc_operation",
        "rotationKeys": rotation_keys,
        "alsoKnownAs": also_known_as,
        "verificationMethods": verification_methods,
        "services": services,
    });

    // Sign the operation: DAG-CBOR encode then sign with the PDS key
    let op_bytes = match cirrus_common::cbor::encode(&operation) {
        Ok(b) => b,
        Err(e) => {
            return PdsError::InvalidRecord(format!("failed to encode operation: {e}"))
                .into_response();
        }
    };

    let signature = match signing_key.sign(&op_bytes) {
        Ok(s) => s,
        Err(e) => {
            return PdsError::InvalidRecord(format!("signing failed: {e}")).into_response();
        }
    };

    // Add signature to operation (base64url-encoded)
    let sig_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &signature,
    );
    operation["sig"] = serde_json::json!(sig_b64);

    Json(SignPlcOperationOutput { operation }).into_response()
}

/// Submits a signed PLC operation to the PLC directory.
async fn submit_plc_operation(
    State(state): State<Arc<AppState>>,
    Json(input): Json<SubmitPlcOperationInput>,
) -> Response {
    // Validate the operation has a signature
    if input.operation.get("sig").is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::invalid_request("operation must be signed")),
        )
            .into_response();
    }

    // Submit to PLC directory
    let plc_url = format!("https://plc.directory/{}", state.did);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return PdsError::Http(e.to_string()).into_response(),
    };

    let response = match client.post(&plc_url).json(&input.operation).send().await {
        Ok(r) => r,
        Err(e) => {
            return PdsError::Http(format!("PLC directory request failed: {e}")).into_response()
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return (
            StatusCode::BAD_GATEWAY,
            Json(XrpcError::new(
                "UpstreamError",
                format!("PLC directory returned {status}: {body}"),
            )),
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

// ============================================================================
// Email endpoints
// ============================================================================

/// Requests an email confirmation token.
///
/// In a full PDS this would send an email; here we create a token and log it
/// (single-user PDS without SMTP).
async fn request_email_confirmation(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Response {
    match state.storage.create_email_token(&auth.did, "confirm_email") {
        Ok(token) => {
            tracing::info!(did = %auth.did, token = %token, "email confirmation token created (no SMTP configured)");
            StatusCode::OK.into_response()
        }
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

/// Confirms an email address with a token.
async fn confirm_email(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
    Json(input): Json<ConfirmEmailInput>,
) -> Response {
    match state
        .storage
        .consume_email_token(&input.token, "confirm_email")
    {
        Ok(Some(email_token)) => {
            if email_token.did != auth.did {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::invalid_request(
                        "Token does not belong to this account",
                    )),
                )
                    .into_response();
            }
            // Store confirmed email
            let _ = state.storage.put_setting("email", &input.email);
            let _ = state.storage.put_setting("email_confirmed", "true");
            StatusCode::OK.into_response()
        }
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::new(
                "ExpiredToken",
                "Confirmation token is invalid or expired",
            )),
        )
            .into_response(),
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

/// Requests a password reset token.
///
/// This endpoint is unauthenticated (user may have forgotten their password).
async fn request_password_reset(
    State(state): State<Arc<AppState>>,
    Json(_input): Json<RequestPasswordResetInput>,
) -> Response {
    // Always return OK to prevent email enumeration.
    // Create the token if the DID is configured.
    if !state.did.is_empty() {
        match state
            .storage
            .create_email_token(&state.did, "reset_password")
        {
            Ok(token) => {
                tracing::info!(token = %token, "password reset token created (no SMTP configured)");
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to create password reset token");
            }
        }
    }
    StatusCode::OK.into_response()
}

/// Resets the account password using a token.
async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ResetPasswordInput>,
) -> Response {
    match state
        .storage
        .consume_email_token(&input.token, "reset_password")
    {
        Ok(Some(_email_token)) => {
            // Hash the new password
            match crate::auth::hash_password(&input.password) {
                Ok(new_hash) => {
                    *state.password_hash.write() = new_hash;
                    // Revoke all refresh tokens for the account
                    let _ = state.storage.revoke_all_refresh_tokens(&state.did);
                    StatusCode::OK.into_response()
                }
                Err(e) => PdsError::AuthFailed(e.to_string()).into_response(),
            }
        }
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::new(
                "ExpiredToken",
                "Reset token is invalid or expired",
            )),
        )
            .into_response(),
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

/// Requests an email update token.
async fn request_email_update(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Response {
    match state.storage.create_email_token(&auth.did, "update_email") {
        Ok(token) => {
            tracing::info!(did = %auth.did, token = %token, "email update token created (no SMTP configured)");
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "tokenRequired": true
                })),
            )
                .into_response()
        }
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

/// Updates the account email with a token.
async fn update_email(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
    Json(input): Json<UpdateEmailInput>,
) -> Response {
    match state
        .storage
        .consume_email_token(&input.token, "update_email")
    {
        Ok(Some(email_token)) => {
            if email_token.did != auth.did {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::invalid_request(
                        "Token does not belong to this account",
                    )),
                )
                    .into_response();
            }
            let _ = state.storage.put_setting("email", &input.email);
            // Mark as unconfirmed since it's a new address
            let _ = state.storage.put_setting("email_confirmed", "false");
            StatusCode::OK.into_response()
        }
        Ok(None) => (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::new(
                "ExpiredToken",
                "Update token is invalid or expired",
            )),
        )
            .into_response(),
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

// ============================================================================
// Account deletion endpoints
// ============================================================================

/// Requests account deletion by creating a `delete_account` token.
async fn request_account_delete(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
) -> Response {
    match state
        .storage
        .create_email_token(&auth.did, "delete_account")
    {
        Ok(token) => {
            tracing::info!(did = %auth.did, token = %token, "account deletion token created (no SMTP configured)");
            StatusCode::OK.into_response()
        }
        Err(e) => PdsError::Storage(e.to_string()).into_response(),
    }
}

/// Deletes the account after verifying password and deletion token.
///
/// This wipes all account data from storage. The DID remains configured
/// but the repo, records, blobs, sessions, and preferences are destroyed.
async fn delete_account(
    State(state): State<Arc<AppState>>,
    Json(input): Json<DeleteAccountInput>,
) -> Response {
    // Verify the DID matches
    if input.did != state.did {
        return (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::invalid_request(
                "DID does not match this server's account",
            )),
        )
            .into_response();
    }

    // Verify password
    let password_hash = state.password_hash();
    if crate::auth::verify_password(&input.password, &password_hash).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(XrpcError::auth_required("Invalid password")),
        )
            .into_response();
    }

    // Verify deletion token
    match state
        .storage
        .consume_email_token(&input.token, "delete_account")
    {
        Ok(Some(email_token)) => {
            if email_token.did != input.did {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::invalid_request(
                        "Token does not belong to this account",
                    )),
                )
                    .into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(XrpcError::new(
                    "ExpiredToken",
                    "Deletion token is invalid or expired",
                )),
            )
                .into_response();
        }
        Err(e) => return PdsError::Storage(e.to_string()).into_response(),
    }

    // Emit a proper #tombstone event so relays/appviews delete cached data
    let seq = state
        .storage
        .get_repo_state()
        .map(|s| s.seq + 1)
        .unwrap_or(1);
    let tombstone = crate::sequencer::FirehoseEvent::Tombstone(crate::sequencer::TombstoneEvent {
        seq,
        did: state.did.clone(),
        time: chrono::Utc::now().to_rfc3339(),
    });

    // Broadcast to live firehose subscribers
    state.firehose.publish(tombstone.clone());

    // Wipe all account data first
    if let Err(e) = state.storage.wipe_account_data() {
        tracing::error!(error = %e, "failed to wipe account data");
        return PdsError::Storage(e.to_string()).into_response();
    }

    // Persist the tombstone event AFTER wipe so it survives for relay replay
    if let Ok(encoded) = tombstone.encode() {
        let _ = state.storage.persist_event("tombstone", &encoded);
    }

    // Notify relay immediately (bypass rate limit — tombstones are critical)
    if let Some(ref crawlers) = state.crawlers {
        crawlers.notify_immediate().await;
    }

    // Clear the password hash so no further logins work
    *state.password_hash.write() = String::new();

    tracing::info!(did = %input.did, "account deleted — all data wiped, tombstone emitted");

    StatusCode::OK.into_response()
}

// ============================================================================
// Moderation endpoints
// ============================================================================

/// Creates a moderation report.
///
/// Proxies the report to the configured appview/moderation service.
/// If no appview is configured, stores the report locally in settings.
async fn create_report(
    State(state): State<Arc<AppState>>,
    RequireAuth(auth): RequireAuth,
    Json(input): Json<CreateReportInput>,
) -> Response {
    // Validate reason_type
    let valid_reasons = [
        "com.atproto.moderation.defs#reasonSpam",
        "com.atproto.moderation.defs#reasonViolation",
        "com.atproto.moderation.defs#reasonMisleading",
        "com.atproto.moderation.defs#reasonSexual",
        "com.atproto.moderation.defs#reasonRude",
        "com.atproto.moderation.defs#reasonOther",
    ];

    if !valid_reasons.contains(&input.reason_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(XrpcError::invalid_request(format!(
                "invalid reasonType: {}",
                input.reason_type
            ))),
        )
            .into_response();
    }

    let now = chrono::Utc::now().to_rfc3339();

    // If appview is configured, proxy the report
    if let (Some(appview), Some(signing_key)) = (&state.appview, &state.signing_key) {
        let body = serde_json::to_vec(&input).unwrap_or_default();
        return crate::pipethrough::proxy_request(
            appview,
            signing_key,
            &state.did,
            &axum::http::Method::POST,
            "/xrpc/com.atproto.moderation.createReport",
            &axum::http::HeaderMap::new(),
            Some(bytes::Bytes::from(body)),
        )
        .await;
    }

    // No appview — store locally with a monotonic ID from settings
    let report_id: i64 = state
        .storage
        .get_setting("next_report_id")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    let _ = state
        .storage
        .put_setting("next_report_id", &(report_id + 1).to_string());

    let output = crate::xrpc::CreateReportOutput {
        id: report_id,
        reason_type: input.reason_type,
        reason: input.reason,
        subject: input.subject,
        reported_by: auth.did,
        created_at: now,
    };

    (StatusCode::OK, Json(output)).into_response()
}

// ============================================================================
// OAuth endpoints
// ============================================================================

/// Query parameters for the authorize GET endpoint.
#[derive(Debug, Deserialize)]
struct OAuthAuthorizeParams {
    /// PAR request URI (clients MUST use PAR per AT Protocol).
    request_uri: String,
}

/// Returns the OAuth authorization server metadata (RFC 8414).
async fn oauth_server_metadata(State(state): State<Arc<AppState>>) -> Response {
    let issuer = format!("https://{}", state.hostname);
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/oauth/par"),
        "revocation_endpoint": format!("{issuer}/oauth/revoke"),
        "scopes_supported": ["atproto", "transition:generic", "transition:chat.bsky"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": true,
        "subject_types_supported": ["public"],
    }))
    .into_response()
}

/// Renders the consent HTML form for the authorization flow.
async fn oauth_authorize_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<OAuthAuthorizeParams>,
) -> Response {
    let oauth_storage = match &state.oauth_storage {
        Some(s) => s,
        None => return (StatusCode::NOT_IMPLEMENTED, "OAuth not configured").into_response(),
    };

    // Validate the request_uri and look up the PAR request (non-consuming)
    let request_uri = &params.request_uri;
    if cirrus_oauth::par::validate_request_uri(request_uri).is_err() {
        return (StatusCode::BAD_REQUEST, "Invalid request_uri format").into_response();
    }

    let par = match oauth_storage.get_par_request(request_uri) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "Unknown or expired request_uri").into_response(),
    };

    if par.is_expired() {
        return (StatusCode::BAD_REQUEST, "Authorization request has expired").into_response();
    }

    // Look up cached client metadata for display
    let client_name = match oauth_storage.get_par_request(request_uri) {
        Some(_) => par.client_id.clone(),
        None => par.client_id.clone(),
    };

    // Render the consent HTML page
    let handle = state.handle();
    let html = render_consent_page(&client_name, &par.scope, &handle, request_uri);

    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

/// Processes the user's consent decision (approve or deny).
async fn oauth_authorize_post(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<OAuthConsentForm>,
) -> Response {
    let oauth_storage = match &state.oauth_storage {
        Some(s) => s,
        None => return (StatusCode::NOT_IMPLEMENTED, "OAuth not configured").into_response(),
    };

    // Consume the PAR request (one-time use)
    let par = match oauth_storage.consume_par_request(&form.request_uri).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (StatusCode::BAD_REQUEST, "Unknown or expired request_uri").into_response()
        }
        Err(e) => return PdsError::OAuth(e).into_response(),
    };

    if par.is_expired() {
        return (StatusCode::BAD_REQUEST, "Authorization request has expired").into_response();
    }

    // User denied consent
    if form.action != "approve" {
        let mut redirect = format!(
            "{}?error=access_denied&error_description=User+denied+consent",
            par.redirect_uri
        );
        if let Some(ref s) = par.state {
            redirect.push_str(&format!("&state={s}"));
        }
        return (StatusCode::SEE_OTHER, [("location", redirect)]).into_response();
    }

    // User approved: generate an authorization code via the provider
    let provider = cirrus_oauth::OAuthProvider::new(
        cirrus_oauth::provider::OAuthProviderConfig {
            issuer: format!("https://{}", state.hostname),
            subject: state.did.clone(),
        },
        OAuthStorageRef(oauth_storage),
    );

    let code = match provider
        .authorize(
            &par.client_id,
            &par.redirect_uri,
            &par.scope,
            &par.code_challenge,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => return PdsError::OAuth(e).into_response(),
    };

    // Redirect back to the client with the authorization code
    let issuer = format!("https://{}", state.hostname);
    let encoded_iss = url::form_urlencoded::byte_serialize(issuer.as_bytes()).collect::<String>();
    let mut redirect = format!("{}?code={}&iss={}", par.redirect_uri, code, encoded_iss,);
    if let Some(ref s) = par.state {
        redirect.push_str(&format!("&state={s}"));
    }

    (StatusCode::SEE_OTHER, [("location", redirect)]).into_response()
}

/// Consent form submission data.
#[derive(Debug, Deserialize)]
struct OAuthConsentForm {
    /// The PAR request URI being authorized.
    request_uri: String,
    /// User action: "approve" or "deny".
    action: String,
}

/// Exchanges an authorization code for tokens (RFC 6749 §4.1.3).
async fn oauth_token(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<OAuthTokenRequest>,
) -> Response {
    let oauth_storage = match &state.oauth_storage {
        Some(s) => s,
        None => {
            return oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "server_error",
                "OAuth not configured",
            )
        }
    };

    let provider = cirrus_oauth::OAuthProvider::new(
        cirrus_oauth::provider::OAuthProviderConfig {
            issuer: format!("https://{}", state.hostname),
            subject: state.did.clone(),
        },
        OAuthStorageRef(oauth_storage),
    );

    // Extract DPoP key thumbprint from the DPoP proof header, if present
    let dpop_jkt = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .and_then(|proof| extract_dpop_jkt(proof));

    match form.grant_type.as_str() {
        "authorization_code" => {
            let code = form.code.as_deref().unwrap_or_default();
            let redirect_uri = form.redirect_uri.as_deref().unwrap_or_default();
            let code_verifier = form.code_verifier.as_deref().unwrap_or_default();

            if code.is_empty() || redirect_uri.is_empty() || code_verifier.is_empty() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Missing required parameters",
                );
            }

            let client_id = form.client_id.as_deref().unwrap_or_default();

            match provider
                .token(code, client_id, redirect_uri, code_verifier, dpop_jkt)
                .await
            {
                Ok(response) => Json(response).into_response(),
                Err(e) => oauth_error_from(e),
            }
        }
        "refresh_token" => {
            let refresh_token = form.refresh_token.as_deref().unwrap_or_default();
            if refresh_token.is_empty() {
                return oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Missing refresh_token",
                );
            }

            match provider.refresh(refresh_token, dpop_jkt).await {
                Ok(response) => Json(response).into_response(),
                Err(e) => oauth_error_from(e),
            }
        }
        _ => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Unsupported grant_type",
        ),
    }
}

/// Token request form data (supports both authorization_code and refresh_token).
#[derive(Debug, Deserialize)]
struct OAuthTokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
}

/// Handles Pushed Authorization Requests (RFC 9126).
async fn oauth_par(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<OAuthParRequest>,
) -> Response {
    let oauth_storage = match &state.oauth_storage {
        Some(s) => s,
        None => {
            return oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "server_error",
                "OAuth not configured",
            )
        }
    };

    if form.response_type != "code" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "response_type must be 'code'",
        );
    }
    if form.code_challenge_method.as_deref() != Some("S256") {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }
    let code_challenge = match &form.code_challenge {
        Some(c) if !c.is_empty() => c.clone(),
        _ => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_challenge is required",
            )
        }
    };

    let par_request = cirrus_oauth::par::ParRequest::new(
        &form.client_id,
        form.redirect_uri.as_deref().unwrap_or_default(),
        form.scope.as_deref().unwrap_or("atproto"),
        &code_challenge,
    );

    let par_request = if let Some(ref s) = form.state {
        par_request.with_state(s)
    } else {
        par_request
    };

    let request_uri = cirrus_oauth::par::generate_request_uri();

    if let Err(e) = oauth_storage
        .save_par_request(&request_uri, par_request)
        .await
    {
        return PdsError::OAuth(e).into_response();
    }

    let response = cirrus_oauth::par::ParResponse::new(request_uri);

    (StatusCode::CREATED, Json(response)).into_response()
}

/// PAR request form data.
#[derive(Debug, Deserialize)]
struct OAuthParRequest {
    response_type: String,
    client_id: String,
    redirect_uri: Option<String>,
    scope: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    state: Option<String>,
}

/// Revokes an OAuth token (RFC 7009).
async fn oauth_revoke(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<OAuthRevokeRequest>,
) -> Response {
    let oauth_storage = match &state.oauth_storage {
        Some(s) => s,
        None => {
            return oauth_error(
                StatusCode::NOT_IMPLEMENTED,
                "server_error",
                "OAuth not configured",
            )
        }
    };

    let provider = cirrus_oauth::OAuthProvider::new(
        cirrus_oauth::provider::OAuthProviderConfig {
            issuer: format!("https://{}", state.hostname),
            subject: state.did.clone(),
        },
        OAuthStorageRef(oauth_storage),
    );

    // Revocation always succeeds per RFC 7009 §2.2
    let _ = provider.revoke(&form.token).await;

    StatusCode::OK.into_response()
}

/// Revoke request form data.
#[derive(Debug, Deserialize)]
struct OAuthRevokeRequest {
    token: String,
}

/// Thin wrapper around `&OAuthSqliteStorage` that implements `OAuthStorage`.
///
/// The `OAuthProvider` is generic over `S: OAuthStorage`, and `OAuthSqliteStorage`
/// implements it. However, we hold an `&OAuthSqliteStorage` reference, so we need
/// this wrapper to delegate trait calls through the reference.
struct OAuthStorageRef<'a>(&'a crate::oauth_storage::OAuthSqliteStorage);

#[async_trait::async_trait]
impl cirrus_oauth::OAuthStorage for OAuthStorageRef<'_> {
    async fn save_auth_code(
        &self,
        data: cirrus_oauth::tokens::AuthCodeData,
    ) -> cirrus_oauth::Result<()> {
        self.0.save_auth_code(data).await
    }
    async fn consume_auth_code(
        &self,
        code: &str,
    ) -> cirrus_oauth::Result<Option<cirrus_oauth::tokens::AuthCodeData>> {
        self.0.consume_auth_code(code).await
    }
    async fn save_token(&self, data: cirrus_oauth::tokens::TokenData) -> cirrus_oauth::Result<()> {
        self.0.save_token(data).await
    }
    async fn get_token_by_access(
        &self,
        access_token: &str,
    ) -> cirrus_oauth::Result<Option<cirrus_oauth::tokens::TokenData>> {
        self.0.get_token_by_access(access_token).await
    }
    async fn get_token_by_refresh(
        &self,
        refresh_token: &str,
    ) -> cirrus_oauth::Result<Option<cirrus_oauth::tokens::TokenData>> {
        self.0.get_token_by_refresh(refresh_token).await
    }
    async fn revoke_token(&self, access_token: &str) -> cirrus_oauth::Result<()> {
        self.0.revoke_token(access_token).await
    }
    async fn revoke_all_tokens(&self, sub: &str) -> cirrus_oauth::Result<()> {
        self.0.revoke_all_tokens(sub).await
    }
    async fn cache_client(
        &self,
        metadata: cirrus_oauth::storage::ClientMetadata,
    ) -> cirrus_oauth::Result<()> {
        self.0.cache_client(metadata).await
    }
    async fn get_cached_client(
        &self,
        client_id: &str,
    ) -> cirrus_oauth::Result<Option<cirrus_oauth::storage::ClientMetadata>> {
        self.0.get_cached_client(client_id).await
    }
    async fn save_par_request(
        &self,
        request_uri: &str,
        request: cirrus_oauth::par::ParRequest,
    ) -> cirrus_oauth::Result<()> {
        self.0.save_par_request(request_uri, request).await
    }
    async fn consume_par_request(
        &self,
        request_uri: &str,
    ) -> cirrus_oauth::Result<Option<cirrus_oauth::par::ParRequest>> {
        self.0.consume_par_request(request_uri).await
    }
    async fn save_nonce(&self, nonce: &str) -> cirrus_oauth::Result<()> {
        self.0.save_nonce(nonce).await
    }
    async fn validate_nonce(&self, nonce: &str) -> cirrus_oauth::Result<bool> {
        self.0.validate_nonce(nonce).await
    }
    async fn cleanup_expired(&self) -> cirrus_oauth::Result<u64> {
        self.0.cleanup_expired().await
    }
}

/// Helper to build an OAuth error JSON response.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": error,
            "error_description": description,
        })),
    )
        .into_response()
}

/// Converts an `OAuthError` into an appropriate HTTP response.
fn oauth_error_from(err: cirrus_oauth::OAuthError) -> Response {
    let (status, error_code) = match &err {
        cirrus_oauth::OAuthError::InvalidClient(_) => (StatusCode::UNAUTHORIZED, "invalid_client"),
        cirrus_oauth::OAuthError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        cirrus_oauth::OAuthError::InvalidScope(_) => (StatusCode::BAD_REQUEST, "invalid_scope"),
        cirrus_oauth::OAuthError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        cirrus_oauth::OAuthError::AccessDenied(_) => (StatusCode::FORBIDDEN, "access_denied"),
        cirrus_oauth::OAuthError::PkceError(_) => (StatusCode::BAD_REQUEST, "invalid_grant"),
        cirrus_oauth::OAuthError::TokenExpired | cirrus_oauth::OAuthError::TokenRevoked => {
            (StatusCode::UNAUTHORIZED, "invalid_grant")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    oauth_error(status, error_code, &err.to_string())
}

/// Extracts the JWK thumbprint from a DPoP proof JWT header.
///
/// For a full implementation this would verify the proof signature;
/// here we just extract the `jwk` from the JWT header and compute
/// its thumbprint.
fn extract_dpop_jkt(proof: &str) -> Option<String> {
    // A DPoP proof is a JWT: header.payload.signature
    let header_b64 = proof.split('.').next()?;
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    let jwk = header.get("jwk")?;

    // Compute JWK thumbprint per RFC 7638: lexicographic JSON of required members
    // For EC keys: {"crv":"...","kty":"...","x":"...","y":"..."}
    let kty = jwk.get("kty")?.as_str()?;
    let canonical = if kty == "EC" {
        let crv = jwk.get("crv")?.as_str()?;
        let x = jwk.get("x")?.as_str()?;
        let y = jwk.get("y")?.as_str()?;
        format!(r#"{{"crv":"{crv}","kty":"{kty}","x":"{x}","y":"{y}"}}"#)
    } else {
        return None; // Only EC keys supported for AT Protocol
    };

    let digest = <sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes());
    Some(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        digest,
    ))
}

/// Renders the HTML consent page shown to the user during OAuth authorization.
fn render_consent_page(client_name: &str, scope: &str, handle: &str, request_uri: &str) -> String {
    // Escape HTML entities to prevent XSS
    let client_name = html_escape(client_name);
    let scope = html_escape(scope);
    let handle = html_escape(handle);
    let request_uri = html_escape(request_uri);

    let scopes_html: String = scope.split(' ').map(|s| format!("<li>{s}</li>")).collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize — {handle}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 20px; color: #1a1a1a; background: #f5f5f5; }}
  .card {{ background: #fff; border-radius: 12px; padding: 32px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  h1 {{ font-size: 1.4em; margin: 0 0 8px; }}
  .subtitle {{ color: #666; margin: 0 0 24px; font-size: 0.95em; }}
  .client {{ font-weight: 600; color: #0066cc; word-break: break-all; }}
  .scopes {{ margin: 16px 0 24px; }}
  .scopes h2 {{ font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.05em; color: #888; margin: 0 0 8px; }}
  .scopes ul {{ margin: 0; padding-left: 20px; }}
  .scopes li {{ margin: 4px 0; font-size: 0.95em; }}
  .actions {{ display: flex; gap: 12px; }}
  .actions button {{ flex: 1; padding: 12px; border-radius: 8px; font-size: 1em; cursor: pointer; border: none; font-weight: 500; }}
  .btn-approve {{ background: #0066cc; color: #fff; }}
  .btn-approve:hover {{ background: #0052a3; }}
  .btn-deny {{ background: #e8e8e8; color: #333; }}
  .btn-deny:hover {{ background: #ddd; }}
</style>
</head>
<body>
<div class="card">
  <h1>Authorization Request</h1>
  <p class="subtitle">Signed in as <strong>@{handle}</strong></p>
  <p><span class="client">{client_name}</span> is requesting access to your account.</p>
  <div class="scopes">
    <h2>Requested permissions</h2>
    <ul>{scopes_html}</ul>
  </div>
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="request_uri" value="{request_uri}">
    <div class="actions">
      <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
      <button type="submit" name="action" value="approve" class="btn-approve">Approve</button>
    </div>
  </form>
</div>
</body>
</html>"#
    )
}

/// Escapes HTML special characters to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ============================================================================
// Pipethrough fallback
// ============================================================================

async fn pipethrough_fallback(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
) -> Response {
    let uri_path = req.uri().path().to_string();

    // Only proxy XRPC requests to the appview
    let nsid: &str = match uri_path.strip_prefix("/xrpc/") {
        Some(rest) => rest.split('?').next().unwrap_or(""),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(XrpcError::new("NotFound", "Not found")),
            )
                .into_response();
        }
    };

    // Check if this NSID should be proxied
    if !crate::pipethrough::should_proxy(nsid) {
        return (
            StatusCode::NOT_FOUND,
            Json(XrpcError::new(
                "MethodNotImplemented",
                format!("Method not implemented: {nsid}"),
            )),
        )
            .into_response();
    }

    // Check appview is configured
    let appview = match &state.appview {
        Some(config) => config,
        None => {
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(XrpcError::new(
                    "NotImplemented",
                    "AppView proxy not configured",
                )),
            )
                .into_response();
        }
    };

    // Signing key is required for service auth
    let signing_key = match &state.signing_key {
        Some(key) => key,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(XrpcError::new(
                    "InternalError",
                    "Signing key not configured",
                )),
            )
                .into_response();
        }
    };

    let method = req.method().clone();
    let uri = req.uri().to_string();
    let headers = req.headers().clone();

    // Read body for POST requests
    let body = if method == axum::http::Method::POST {
        match axum::body::to_bytes(req.into_body(), 2 * 1024 * 1024).await {
            Ok(b) => Some(b),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(XrpcError::invalid_request("Failed to read request body")),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    let response = crate::pipethrough::proxy_request(
        appview,
        signing_key,
        &state.did,
        &method,
        &uri,
        &headers,
        body,
    )
    .await;

    // Apply read-after-write munging if applicable
    if !crate::read_after_write::needs_read_after_write(nsid) {
        return response;
    }

    // Extract requester DID from auth header (if present)
    let requester_did = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|token| {
            cirrus_common::jwt::decode_unverified::<cirrus_common::jwt::Claims>(token)
                .ok()
                .map(|c| c.sub.unwrap_or(c.iss))
        });

    let Some(requester_did) = requester_did else {
        return response;
    };

    // Only munge responses for the local user
    if requester_did != state.did {
        return response;
    }

    let (parts, body) = response.into_parts();

    // Check for repo rev header
    let Some(appview_rev) = crate::read_after_write::get_repo_rev(&parts.headers) else {
        return Response::from_parts(parts, body);
    };

    // Only process JSON responses
    let is_json = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map_or(false, |ct| ct.contains("application/json"));

    if !is_json {
        return Response::from_parts(parts, body);
    }

    // Get local records since the appview's revision
    let local = crate::read_after_write::get_local_records(&state.storage, appview_rev);

    if local.count == 0 {
        return Response::from_parts(parts, body);
    }

    // Buffer and parse the response body
    let body_bytes = match axum::body::to_bytes(body, 4 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "Failed to buffer upstream response",
            )
                .into_response();
        }
    };

    let parsed: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            // Can't parse JSON, return original response
            return (parts.status, parts.headers, body_bytes).into_response();
        }
    };

    // Munge the response with local data
    let handle = state.handle();
    match crate::read_after_write::munge_response(nsid, parsed, &local, &requester_did, &handle) {
        Some(munged) => {
            let mut headers = parts.headers;
            // Add upstream lag header
            if let Some(lag) = crate::read_after_write::get_local_lag(&local) {
                if let Ok(v) = axum::http::HeaderValue::from_str(&lag.to_string()) {
                    headers.insert("atproto-upstream-lag", v);
                }
            }
            (parts.status, headers, Json(munged)).into_response()
        }
        None => (parts.status, parts.headers, body_bytes).into_response(),
    }
}

// ============================================================================
// Error handling
// ============================================================================

impl IntoResponse for PdsError {
    fn into_response(self) -> axum::response::Response {
        let (status, error) = match &self {
            Self::RepoNotFound(_) => (
                StatusCode::NOT_FOUND,
                XrpcError::new("RepoNotFound", self.to_string()),
            ),
            Self::RecordNotFound(_) => (
                StatusCode::NOT_FOUND,
                XrpcError::record_not_found(self.to_string()),
            ),
            Self::InvalidRecord(_) | Self::Lexicon(_) | Self::Validation(_) => (
                StatusCode::BAD_REQUEST,
                XrpcError::invalid_request(self.to_string()),
            ),
            Self::AuthFailed(_) => (
                StatusCode::UNAUTHORIZED,
                XrpcError::auth_required(self.to_string()),
            ),
            Self::NotAuthorized(_) => (
                StatusCode::FORBIDDEN,
                XrpcError::new("NotAuthorized", self.to_string()),
            ),
            Self::AccountDeactivated => (StatusCode::FORBIDDEN, XrpcError::account_deactivated()),
            Self::InvalidSwap(_) => (
                StatusCode::BAD_REQUEST,
                XrpcError::new("InvalidSwap", self.to_string()),
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                XrpcError::new("RateLimited", "Too many requests"),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                XrpcError::new("InternalError", self.to_string()),
            ),
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
            password_hash: parking_lot::RwLock::new(String::new()),
            hostname: "test.local".to_string(),
            did: "did:plc:test".to_string(),
            handle: parking_lot::RwLock::new("test.local".to_string()),
            public_key_multibase: "zQ3shtest".to_string(),
            firehose: Firehose::new(),
            blob_store: Box::new(crate::blobs::MemoryBlobStore::new()),
            handle_resolver: crate::handle::HandleResolver::new(),
            rate_limits: None,
            oauth_storage: None,
            signing_key: None,
            crawlers: None,
            appview: None,
        });

        let _router = create_router(state);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b\"c"), "a&amp;b&quot;c");
        assert_eq!(html_escape("safe text"), "safe text");
    }

    #[test]
    fn test_oauth_error_response_mapping() {
        let err = cirrus_oauth::OAuthError::InvalidGrant("bad code".into());
        let resp = oauth_error_from(err);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let err = cirrus_oauth::OAuthError::InvalidClient("unknown".into());
        let resp = oauth_error_from(err);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let err = cirrus_oauth::OAuthError::TokenExpired;
        let resp = oauth_error_from(err);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_render_consent_page_contains_required_elements() {
        let html = render_consent_page(
            "did:web:example.com",
            "atproto transition:generic",
            "alice.test",
            "urn:ietf:params:oauth:request_uri:abc123",
        );

        assert!(html.contains("did:web:example.com"));
        assert!(html.contains("alice.test"));
        assert!(html.contains("atproto"));
        assert!(html.contains("transition:generic"));
        assert!(html.contains("urn:ietf:params:oauth:request_uri:abc123"));
        assert!(html.contains("<form"));
        assert!(html.contains("approve"));
        assert!(html.contains("deny"));
    }

    #[test]
    fn test_consent_page_escapes_xss() {
        let html = render_consent_page(
            "<script>alert(1)</script>",
            "atproto",
            "handle.test",
            "urn:ietf:params:oauth:request_uri:test",
        );

        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
