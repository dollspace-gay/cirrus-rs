//! Integration tests for the PDS XRPC endpoints.
//!
//! Tests the full HTTP request/response cycle through the axum router,
//! verifying status codes, response bodies, and auth enforcement.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use tower::ServiceExt;

use cirrus_pds::blobs::MemoryBlobStore;
use cirrus_pds::handle::HandleResolver;
use cirrus_pds::lexicon::LexiconStore;
use cirrus_pds::routes::{create_router, AppState};
use cirrus_pds::sequencer::Firehose;
use cirrus_pds::storage::SqliteStorage;

const TEST_DID: &str = "did:plc:testuser123";
const TEST_HANDLE: &str = "test.example.com";
const TEST_JWT_SECRET: &[u8] = b"integration-test-jwt-secret-key";
const TEST_PASSWORD: &str = "test-password-2024";

/// Creates a test AppState with in-memory storage and a known password hash.
fn test_state() -> Arc<AppState> {
    let storage = SqliteStorage::in_memory().expect("create test storage");
    let password_hash =
        cirrus_pds::auth::hash_password(TEST_PASSWORD).expect("hash password");

    Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: TEST_JWT_SECRET.to_vec(),
        password_hash,
        hostname: "test.example.com".to_string(),
        did: TEST_DID.to_string(),
        handle: TEST_HANDLE.to_string(),
        public_key_multibase: "zQ3shtest123".to_string(),
        firehose: Firehose::new(),
        blob_store: Box::new(MemoryBlobStore::new()),
        handle_resolver: HandleResolver::new(),
        rate_limits: None, // Disable rate limiting in tests
        oauth_storage: None,
        signing_key: None,
    })
}

/// Helper to create a session and get the access JWT.
async fn get_access_token(state: Arc<AppState>) -> String {
    let app = create_router(state);
    let body = serde_json::json!({
        "identifier": TEST_HANDLE,
        "password": TEST_PASSWORD
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.server.createSession")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    session["accessJwt"].as_str().unwrap().to_string()
}

/// Helper to get a refresh JWT.
async fn get_refresh_token(state: Arc<AppState>) -> String {
    let app = create_router(state);
    let body = serde_json::json!({
        "identifier": TEST_HANDLE,
        "password": TEST_PASSWORD
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.server.createSession")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    session["refreshJwt"].as_str().unwrap().to_string()
}

/// Helper to send a GET request with optional auth.
async fn get(
    state: Arc<AppState>,
    uri: &str,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let app = create_router(state);
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Helper to send a POST request with JSON body and optional auth.
async fn post_json(
    state: Arc<AppState>,
    uri: &str,
    body: &serde_json::Value,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let app = create_router(state);
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ==========================================================================
// Public endpoint tests
// ==========================================================================

#[tokio::test]
async fn test_health_check() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"OK");
}

#[tokio::test]
async fn test_describe_server() {
    let state = test_state();
    let (status, json) = get(state, "/xrpc/com.atproto.server.describeServer", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], "did:web:test.example.com");
    assert_eq!(json["inviteCodeRequired"], false);
}

#[tokio::test]
async fn test_well_known_atproto_did() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .uri("/.well-known/atproto-did")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(std::str::from_utf8(&body).unwrap(), TEST_DID);
}

#[tokio::test]
async fn test_well_known_did_json() {
    let state = test_state();
    let (status, json) = get(state, "/.well-known/did.json", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["id"], TEST_DID);
    assert!(json["verificationMethod"].is_array());
    assert!(json["service"].is_array());
}

#[tokio::test]
async fn test_resolve_handle_local() {
    let state = test_state();
    let uri = format!(
        "/xrpc/com.atproto.identity.resolveHandle?handle={}",
        TEST_HANDLE
    );
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
}

#[tokio::test]
async fn test_describe_repo() {
    let state = test_state();
    let uri = format!("/xrpc/com.atproto.repo.describeRepo?repo={TEST_DID}");
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
    assert_eq!(json["handle"], TEST_HANDLE);
    assert!(json["collections"].is_array());
    assert_eq!(json["handleIsCorrect"], true);
}

#[tokio::test]
async fn test_describe_repo_by_handle() {
    let state = test_state();
    let uri = format!("/xrpc/com.atproto.repo.describeRepo?repo={TEST_HANDLE}");
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
}

#[tokio::test]
async fn test_describe_repo_not_found() {
    let state = test_state();
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.repo.describeRepo?repo=did:plc:unknown",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RepoNotFound");
}

// ==========================================================================
// Authentication tests
// ==========================================================================

#[tokio::test]
async fn test_create_session_by_handle() {
    let state = test_state();
    let body = serde_json::json!({
        "identifier": TEST_HANDLE,
        "password": TEST_PASSWORD
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["accessJwt"].is_string());
    assert!(json["refreshJwt"].is_string());
    assert_eq!(json["did"], TEST_DID);
    assert_eq!(json["handle"], TEST_HANDLE);
}

#[tokio::test]
async fn test_create_session_by_did() {
    let state = test_state();
    let body = serde_json::json!({
        "identifier": TEST_DID,
        "password": TEST_PASSWORD
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
}

#[tokio::test]
async fn test_create_session_wrong_password() {
    let state = test_state();
    let body = serde_json::json!({
        "identifier": TEST_HANDLE,
        "password": "wrong-password"
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_create_session_wrong_identifier() {
    let state = test_state();
    let body = serde_json::json!({
        "identifier": "unknown@example.com",
        "password": TEST_PASSWORD
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_get_session_authenticated() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.getSession",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
    assert_eq!(json["handle"], TEST_HANDLE);
    assert_eq!(json["active"], true);
}

#[tokio::test]
async fn test_get_session_no_auth() {
    let state = test_state();
    let (status, json) = get(state, "/xrpc/com.atproto.server.getSession", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_get_session_invalid_token() {
    let state = test_state();
    let (status, _) = get(
        state,
        "/xrpc/com.atproto.server.getSession",
        Some("invalid-jwt-token"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_token_rejected_on_normal_endpoint() {
    let state = test_state();
    let refresh_token = get_refresh_token(Arc::clone(&state)).await;
    // Refresh token should be rejected on a normal authenticated endpoint
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.getSession",
        Some(&refresh_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        json["message"]
            .as_str()
            .unwrap_or("")
            .contains("refresh token"),
        "should mention refresh token: {}",
        json
    );
}

// ==========================================================================
// Record CRUD tests
// ==========================================================================

#[tokio::test]
async fn test_create_and_get_record() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create a record
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "Integration test post",
            "createdAt": "2026-02-16T00:00:00Z"
        }
    });
    let (status, create_json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(create_json["uri"].as_str().unwrap().starts_with("at://"));
    assert!(create_json["cid"].is_string());

    // Extract rkey from URI
    let uri = create_json["uri"].as_str().unwrap();
    let rkey = uri.rsplit('/').next().unwrap();

    // Get the record back
    let get_uri = format!(
        "/xrpc/com.atproto.repo.getRecord?repo={TEST_DID}&collection=app.bsky.feed.post&rkey={rkey}"
    );
    let (status, get_json) = get(Arc::clone(&state), &get_uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(get_json["value"]["text"], "Integration test post");
    assert_eq!(get_json["uri"], uri);
}

#[tokio::test]
async fn test_list_records() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create 3 records
    for i in 0..3 {
        let body = serde_json::json!({
            "repo": TEST_DID,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": format!("Post {i}"),
                "createdAt": "2026-02-16T00:00:00Z"
            }
        });
        let (status, _) = post_json(
            Arc::clone(&state),
            "/xrpc/com.atproto.repo.createRecord",
            &body,
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // List records
    let uri = format!(
        "/xrpc/com.atproto.repo.listRecords?repo={TEST_DID}&collection=app.bsky.feed.post"
    );
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["records"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_list_records_with_limit() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    for i in 0..5 {
        let body = serde_json::json!({
            "repo": TEST_DID,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": format!("Post {i}"),
                "createdAt": "2026-02-16T00:00:00Z"
            }
        });
        post_json(
            Arc::clone(&state),
            "/xrpc/com.atproto.repo.createRecord",
            &body,
            Some(&token),
        )
        .await;
    }

    let uri = format!(
        "/xrpc/com.atproto.repo.listRecords?repo={TEST_DID}&collection=app.bsky.feed.post&limit=2"
    );
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["records"].as_array().unwrap().len(), 2);
    assert!(json["cursor"].is_string()); // Should have pagination cursor
}

#[tokio::test]
async fn test_delete_record() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "To be deleted",
            "createdAt": "2026-02-16T00:00:00Z"
        }
    });
    let (_, create_json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    let rkey = create_json["uri"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();

    // Delete
    let del_body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "rkey": rkey
    });
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.deleteRecord",
        &del_body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify deleted
    let get_uri = format!(
        "/xrpc/com.atproto.repo.getRecord?repo={TEST_DID}&collection=app.bsky.feed.post&rkey={rkey}"
    );
    let (status, _) = get(state, &get_uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_put_record() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.actor.profile",
        "rkey": "self",
        "record": {
            "$type": "app.bsky.actor.profile",
            "displayName": "Test User"
        }
    });
    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.putRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["uri"].as_str().unwrap().contains("app.bsky.actor.profile/self"));
}

#[tokio::test]
async fn test_create_record_no_auth() {
    let state = test_state();
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {"text": "test"}
    });
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_record_repo_mismatch() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": "did:plc:someone_else",
        "collection": "app.bsky.feed.post",
        "record": {"text": "test"}
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "NotAuthorized");
}

#[tokio::test]
async fn test_get_record_not_found() {
    let state = test_state();
    let (status, json) = get(
        state,
        &format!(
            "/xrpc/com.atproto.repo.getRecord?repo={TEST_DID}&collection=app.bsky.feed.post&rkey=nonexistent"
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RecordNotFound");
}

// ==========================================================================
// Input validation tests (security)
// ==========================================================================

#[tokio::test]
async fn test_reject_path_traversal_in_rkey() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "rkey": "../../../etc/passwd",
        "record": {"$type": "app.bsky.feed.post", "text": "test", "createdAt": "2026-01-01T00:00:00Z"}
    });
    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_reject_path_traversal_in_collection() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "../../../etc/passwd",
        "record": {"text": "test"}
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_reject_invalid_collection_nsid() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "post",
        "record": {"text": "test"}
    });
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_reject_null_bytes_in_rkey() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "rkey": "test\u{0000}evil",
        "record": {"$type": "app.bsky.feed.post", "text": "test", "createdAt": "2026-01-01T00:00:00Z"}
    });
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_reject_oversized_record() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create a record with text > 64KB
    let huge_text = "x".repeat(70_000);
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": huge_text,
            "createdAt": "2026-01-01T00:00:00Z"
        }
    });
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_sql_injection_in_identifier() {
    let state = test_state();
    let body = serde_json::json!({
        "identifier": "' OR 1=1 --",
        "password": "test"
    });
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &body,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "AuthenticationRequired");
}

// ==========================================================================
// Preferences tests
// ==========================================================================

#[tokio::test]
async fn test_preferences_crud() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Get empty preferences
    let (status, json) = get(
        Arc::clone(&state),
        "/xrpc/app.bsky.actor.getPreferences",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["preferences"].as_array().unwrap().is_empty());

    // Put preferences
    let body = serde_json::json!({
        "preferences": [
            {"$type": "app.bsky.actor.defs#savedFeedsPrefV2", "items": []}
        ]
    });
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/app.bsky.actor.putPreferences",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify persisted
    let (status, json) = get(
        state,
        "/xrpc/app.bsky.actor.getPreferences",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["preferences"].as_array().unwrap().len(), 1);
}

// ==========================================================================
// Blob upload tests
// ==========================================================================

#[tokio::test]
async fn test_upload_blob() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let app = create_router(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "text/plain")
        .body(Body::from("hello blob world"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["blob"]["$type"], "blob");
    assert_eq!(json["blob"]["mimeType"], "text/plain");
    assert_eq!(json["blob"]["size"], 16);
}

#[tokio::test]
async fn test_upload_blob_no_auth() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "text/plain")
        .body(Body::from("hello"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ==========================================================================
// Account management tests
// ==========================================================================

#[tokio::test]
async fn test_check_account_status() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.checkAccountStatus",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["activated"], true);
    assert_eq!(json["validDid"], true);
}

#[tokio::test]
async fn test_deactivate_and_activate_account() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Deactivate
    let body = serde_json::json!({});
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.deactivateAccount",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify records can't be created while deactivated
    let record_body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {"$type": "app.bsky.feed.post", "text": "test", "createdAt": "2026-01-01T00:00:00Z"}
    });
    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &record_body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(json["error"], "AccountDeactivated");

    // Reactivate
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.activateAccount",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify records can be created again
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &record_body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ==========================================================================
// Sync endpoint tests
// ==========================================================================

#[tokio::test]
async fn test_get_latest_commit() {
    let state = test_state();
    let uri = format!(
        "/xrpc/com.atproto.sync.getLatestCommit?did={TEST_DID}"
    );
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    // Initial state may have null commit
    assert!(json.get("cid").is_some());
    assert!(json.get("rev").is_some());
}

#[tokio::test]
async fn test_get_latest_commit_wrong_did() {
    let state = test_state();
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.sync.getLatestCommit?did=did:plc:unknown",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RepoNotFound");
}

#[tokio::test]
async fn test_get_head() {
    let state = test_state();
    let (status, json) = get(state, "/xrpc/com.atproto.sync.getHead", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("root").is_some());
}

#[tokio::test]
async fn test_get_repo() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create a record first so repo has content
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "repo test",
            "createdAt": "2026-02-16T00:00:00Z"
        }
    });
    post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;

    // Get repo (returns CAR binary)
    let app = create_router(state);
    let req = Request::builder()
        .uri(&format!(
            "/xrpc/com.atproto.sync.getRepo?did={TEST_DID}"
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(ct, "application/vnd.ipld.car");

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_get_repo_wrong_did() {
    let state = test_state();
    let (status, _) = get(
        state,
        "/xrpc/com.atproto.sync.getRepo?did=did:plc:unknown",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ==========================================================================
// Method enforcement tests
// ==========================================================================

#[tokio::test]
async fn test_post_on_get_endpoint_returns_405() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.server.describeServer")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_get_on_post_endpoint_returns_405() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .method(Method::GET)
        .uri("/xrpc/com.atproto.server.createSession")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_unknown_route_returns_404() {
    let state = test_state();
    let app = create_router(state);
    let req = Request::builder()
        .uri("/xrpc/com.atproto.nonexistent.method")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ==========================================================================
// Firehose test
// ==========================================================================

#[tokio::test]
async fn test_firehose_event_on_create_record() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Subscribe to firehose before creating record
    let mut rx = state.firehose.subscribe();

    // Create a record
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "firehose test",
            "createdAt": "2026-02-16T00:00:00Z"
        }
    });
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify firehose received the event
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout waiting for firehose event")
        .expect("recv error");

    match &*event {
        cirrus_pds::sequencer::FirehoseEvent::Commit(c) => {
            assert_eq!(c.repo, TEST_DID);
            assert_eq!(c.ops.len(), 1);
            assert_eq!(c.ops[0].action, "create");
            assert!(c.ops[0].path.starts_with("app.bsky.feed.post/"));
        }
    }
}

// ==========================================================================
// Delete session test
// ==========================================================================

#[tokio::test]
async fn test_delete_session() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.server.deleteSession",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
