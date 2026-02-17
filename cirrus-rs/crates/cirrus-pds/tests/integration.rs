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
    let password_hash = cirrus_pds::auth::hash_password(TEST_PASSWORD).expect("hash password");

    Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: TEST_JWT_SECRET.to_vec(),
        password_hash: parking_lot::RwLock::new(password_hash),
        hostname: "test.example.com".to_string(),
        did: TEST_DID.to_string(),
        handle: parking_lot::RwLock::new(TEST_HANDLE.to_string()),
        public_key_multibase: "zQ3shtest123".to_string(),
        firehose: Firehose::new(),
        blob_store: Box::new(MemoryBlobStore::new()),
        handle_resolver: HandleResolver::new(),
        rate_limits: None, // Disable rate limiting in tests
        oauth_storage: None,
        signing_key: None,
        crawlers: None,
        appview: None,
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
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
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
    let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
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
    let (status, json) =
        post_json(state, "/xrpc/com.atproto.server.createSession", &body, None).await;
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
    let (status, json) =
        post_json(state, "/xrpc/com.atproto.server.createSession", &body, None).await;
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
    let (status, json) =
        post_json(state, "/xrpc/com.atproto.server.createSession", &body, None).await;
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
    let (status, json) =
        post_json(state, "/xrpc/com.atproto.server.createSession", &body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["error"], "AuthenticationRequired");
}

#[tokio::test]
async fn test_get_session_authenticated() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;
    let (status, json) = get(state, "/xrpc/com.atproto.server.getSession", Some(&token)).await;
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
    let uri =
        format!("/xrpc/com.atproto.repo.listRecords?repo={TEST_DID}&collection=app.bsky.feed.post");
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
    assert!(json["uri"]
        .as_str()
        .unwrap()
        .contains("app.bsky.actor.profile/self"));
}

#[tokio::test]
async fn test_create_record_no_auth() {
    let state = test_state();
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {"text": "test"}
    });
    let (status, _) = post_json(state, "/xrpc/com.atproto.repo.createRecord", &body, None).await;
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
    let (status, json) =
        post_json(state, "/xrpc/com.atproto.server.createSession", &body, None).await;
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
    let (status, json) = get(state, "/xrpc/app.bsky.actor.getPreferences", Some(&token)).await;
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
    let uri = format!("/xrpc/com.atproto.sync.getLatestCommit?did={TEST_DID}");
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
        .uri(&format!("/xrpc/com.atproto.sync.getRepo?did={TEST_DID}"))
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
        cirrus_pds::sequencer::FirehoseEvent::Tombstone(_) => {
            panic!("expected Commit event, got Tombstone");
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

// ==========================================================================
// applyWrites tests
// ==========================================================================

#[tokio::test]
async fn test_apply_writes_batch_create() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {"text": "post one", "$type": "app.bsky.feed.post"}
            },
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {"text": "post two", "$type": "app.bsky.feed.post"}
            }
        ]
    });

    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.applyWrites",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["commit"]["cid"].is_string());
    assert!(json["commit"]["rev"].is_string());

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0]["uri"]
        .as_str()
        .unwrap()
        .contains("app.bsky.feed.post"));
    assert!(results[0]["cid"].is_string());
    assert!(results[1]["uri"]
        .as_str()
        .unwrap()
        .contains("app.bsky.feed.post"));
}

#[tokio::test]
async fn test_apply_writes_mixed_ops() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // First create a record
    let (status, created) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &serde_json::json!({
            "repo": TEST_DID,
            "collection": "app.bsky.feed.post",
            "rkey": "mixedtest1",
            "record": {"text": "will update", "$type": "app.bsky.feed.post"}
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(created["uri"].is_string());

    // Batch: create one, update the existing, delete nothing (another create)
    let body = serde_json::json!({
        "repo": TEST_DID,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "rkey": "mixedtest2",
                "value": {"text": "new post", "$type": "app.bsky.feed.post"}
            },
            {
                "$type": "com.atproto.repo.applyWrites#update",
                "collection": "app.bsky.feed.post",
                "rkey": "mixedtest1",
                "value": {"text": "updated post", "$type": "app.bsky.feed.post"}
            },
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": "mixedtest2"
            }
        ]
    });

    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.applyWrites",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 3);
    // First result is create
    assert!(results[0]["uri"].is_string());
    assert!(results[0]["cid"].is_string());
    // Second result is update
    assert!(results[1]["uri"].is_string());
    // Third result is delete (empty object)
    assert!(results[2].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn test_apply_writes_no_auth() {
    let state = test_state();

    let body = serde_json::json!({
        "repo": TEST_DID,
        "writes": []
    });

    let (status, _) = post_json(state, "/xrpc/com.atproto.repo.applyWrites", &body, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_apply_writes_too_many() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Build 201 writes (exceeds MAX_APPLY_WRITES of 200)
    let writes: Vec<serde_json::Value> = (0..201)
        .map(|i| {
            serde_json::json!({
                "$type": "com.atproto.repo.applyWrites#create",
                "collection": "app.bsky.feed.post",
                "value": {"text": format!("post {i}"), "$type": "app.bsky.feed.post"}
            })
        })
        .collect();

    let body = serde_json::json!({
        "repo": TEST_DID,
        "writes": writes
    });

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.repo.applyWrites",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("too many writes"));
}

#[tokio::test]
async fn test_apply_writes_delete_nonexistent() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let body = serde_json::json!({
        "repo": TEST_DID,
        "writes": [
            {
                "$type": "com.atproto.repo.applyWrites#delete",
                "collection": "app.bsky.feed.post",
                "rkey": "nonexistent"
            }
        ]
    });

    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.repo.applyWrites",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ============================================================================
// getServiceAuth tests
// ============================================================================

/// Creates a test AppState with a signing key for service auth tests.
fn test_state_with_signing_key() -> Arc<AppState> {
    let storage = SqliteStorage::in_memory().expect("create test storage");
    let password_hash = cirrus_pds::auth::hash_password(TEST_PASSWORD).expect("hash password");
    let signing_key = cirrus_common::crypto::Keypair::generate();

    Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: TEST_JWT_SECRET.to_vec(),
        password_hash: parking_lot::RwLock::new(password_hash),
        hostname: "test.example.com".to_string(),
        did: TEST_DID.to_string(),
        handle: parking_lot::RwLock::new(TEST_HANDLE.to_string()),
        public_key_multibase: "zQ3shtest123".to_string(),
        firehose: Firehose::new(),
        blob_store: Box::new(MemoryBlobStore::new()),
        handle_resolver: HandleResolver::new(),
        rate_limits: None,
        oauth_storage: None,
        signing_key: Some(signing_key),
        crawlers: None,
        appview: None,
    })
}

#[tokio::test]
async fn test_get_service_auth() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, json) = get(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:appview.example.com&lxm=com.atproto.repo.createRecord",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let service_token = json["token"].as_str().unwrap();

    // Verify the token is a valid JWT with 3 parts
    assert_eq!(service_token.split('.').count(), 3);

    // Decode the claims without verification to check structure
    let claims: cirrus_common::jwt::Claims =
        cirrus_common::jwt::decode_unverified(service_token).unwrap();
    assert_eq!(claims.iss, TEST_DID);
    assert_eq!(claims.aud, Some("did:web:appview.example.com".to_string()));
    assert_eq!(
        claims.lxm,
        Some("com.atproto.repo.createRecord".to_string())
    );
    assert!(claims.jti.is_some());
    assert!(!claims.is_expired());
}

#[tokio::test]
async fn test_get_service_auth_no_auth() {
    let state = test_state_with_signing_key();

    let (status, _) = get(
        state,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:example.com",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_get_service_auth_no_signing_key() {
    // Use default test_state (no signing key)
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:example.com",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["message"].as_str().unwrap().contains("signing key"));
}

#[tokio::test]
async fn test_get_service_auth_exp_too_long() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    // Without lxm, max is 60 seconds
    let (status, json) = get(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:example.com&exp=300",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("expiration too long"));
}

#[tokio::test]
async fn test_get_service_auth_invalid_aud() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, _) = get(
        state,
        "/xrpc/com.atproto.server.getServiceAuth?aud=not-a-did",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ============================================================================
// getRepoStatus tests
// ============================================================================

#[tokio::test]
async fn test_get_repo_status() {
    let state = test_state();
    let uri = format!("/xrpc/com.atproto.sync.getRepoStatus?did={TEST_DID}");
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
    assert!(json["active"].is_boolean());
}

#[tokio::test]
async fn test_get_repo_status_wrong_did() {
    let state = test_state();
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.sync.getRepoStatus?did=did:plc:unknown",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RepoNotFound");
}

// ============================================================================
// listRepos tests
// ============================================================================

#[tokio::test]
async fn test_list_repos() {
    let state = test_state();
    let (status, json) = get(state, "/xrpc/com.atproto.sync.listRepos", None).await;
    assert_eq!(status, StatusCode::OK);
    let repos = json["repos"].as_array().unwrap();
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["did"], TEST_DID);
    assert!(repos[0]["active"].is_boolean());
}

#[tokio::test]
async fn test_list_repos_with_cursor() {
    let state = test_state();
    // With a cursor, single-user PDS should return empty
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.sync.listRepos?cursor=somecursor",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let repos = json["repos"].as_array().unwrap();
    assert_eq!(repos.len(), 0);
}

// ============================================================================
// listBlobs tests
// ============================================================================

#[tokio::test]
async fn test_list_blobs_empty() {
    let state = test_state();
    let uri = format!("/xrpc/com.atproto.sync.listBlobs?did={TEST_DID}");
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let cids = json["cids"].as_array().unwrap();
    assert!(cids.is_empty());
}

#[tokio::test]
async fn test_list_blobs_after_upload() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Upload a blob
    let app = create_router(Arc::clone(&state));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/xrpc/com.atproto.repo.uploadBlob")
        .header("content-type", "image/png")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(vec![
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        ]))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List blobs should include the uploaded blob
    let uri = format!("/xrpc/com.atproto.sync.listBlobs?did={TEST_DID}");
    let (status, json) = get(state, &uri, None).await;
    assert_eq!(status, StatusCode::OK);
    let cids = json["cids"].as_array().unwrap();
    assert_eq!(cids.len(), 1);
}

#[tokio::test]
async fn test_list_blobs_wrong_did() {
    let state = test_state();
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.sync.listBlobs?did=did:plc:unknown",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RepoNotFound");
}

// ============================================================================
// getBlocks tests
// ============================================================================

#[tokio::test]
async fn test_get_blocks() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    // Create a record to get blocks into storage
    let body = serde_json::json!({
        "repo": TEST_DID,
        "collection": "app.bsky.feed.post",
        "record": {
            "$type": "app.bsky.feed.post",
            "text": "blocks test",
            "createdAt": "2026-02-16T00:00:00Z"
        }
    });
    let (status, created) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.repo.createRecord",
        &body,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let record_cid = created["cid"].as_str().unwrap();

    // getBlocks with the record's CID
    let app = create_router(Arc::clone(&state));
    let req = Request::builder()
        .uri(&format!(
            "/xrpc/com.atproto.sync.getBlocks?did={TEST_DID}&cids={record_cid}"
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

    let car_body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(!car_body.is_empty());
}

#[tokio::test]
async fn test_get_blocks_wrong_did() {
    let state = test_state();
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.sync.getBlocks?did=did:plc:unknown&cids=bafytest",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"], "RepoNotFound");
}

// ============================================================================
// requestCrawl / notifyOfUpdate tests
// ============================================================================

#[tokio::test]
async fn test_request_crawl() {
    let state = test_state();
    let body = serde_json::json!({ "hostname": "other-pds.example.com" });
    let (status, _) = post_json(state, "/xrpc/com.atproto.sync.requestCrawl", &body, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_notify_of_update_endpoint() {
    let state = test_state();
    let body = serde_json::json!({ "hostname": "other-pds.example.com" });
    let (status, _) = post_json(state, "/xrpc/com.atproto.sync.notifyOfUpdate", &body, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ============================================================================
// Pipethrough fallback tests
// ============================================================================

#[tokio::test]
async fn test_pipethrough_no_appview_configured() {
    // Without appview configured, app.bsky.* should return 501
    let state = test_state();
    let (status, json) = get(state, "/xrpc/app.bsky.feed.getTimeline", None).await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(json["error"].as_str().unwrap(), "NotImplemented");
}

#[tokio::test]
async fn test_pipethrough_unknown_com_atproto_method() {
    // Unknown com.atproto.* methods should return MethodNotImplemented
    let state = test_state();
    let (status, json) = get(state, "/xrpc/com.atproto.nonexistent.method", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(json["error"].as_str().unwrap(), "MethodNotImplemented");
}

// ==========================================================================
// App password tests
// ==========================================================================

#[tokio::test]
async fn test_create_app_password() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "My Test App" }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "My Test App");
    assert!(!json["privileged"].as_bool().unwrap());
    assert!(json["createdAt"].as_str().is_some());

    // Password should be in xxxx-xxxx-xxxx-xxxx format
    let password = json["password"].as_str().unwrap();
    let parts: Vec<&str> = password.split('-').collect();
    assert_eq!(parts.len(), 4);
    for part in &parts {
        assert_eq!(part.len(), 4);
    }
}

#[tokio::test]
async fn test_create_app_password_privileged() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "Admin App", "privileged": true }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["name"], "Admin App");
    assert!(json["privileged"].as_bool().unwrap());
}

#[tokio::test]
async fn test_create_app_password_requires_auth() {
    let state = test_state();

    let (status, _json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "Unauthed App" }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_list_app_passwords() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Initially empty
    let (status, json) = get(
        state.clone(),
        "/xrpc/com.atproto.server.listAppPasswords",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["passwords"].as_array().unwrap().len(), 0);

    // Create two app passwords
    post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "App One" }),
        Some(&token),
    )
    .await;

    post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "App Two", "privileged": true }),
        Some(&token),
    )
    .await;

    // List should show both
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.listAppPasswords",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let passwords = json["passwords"].as_array().unwrap();
    assert_eq!(passwords.len(), 2);

    // Should not contain password hashes or plaintext
    for p in passwords {
        assert!(p.get("password").is_none());
        assert!(p.get("password_hash").is_none());
        assert!(p["name"].as_str().is_some());
        assert!(p["createdAt"].as_str().is_some());
    }
}

#[tokio::test]
async fn test_revoke_app_password() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Create an app password
    post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "To Revoke" }),
        Some(&token),
    )
    .await;

    // Revoke it
    let (status, _json) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.revokeAppPassword",
        &serde_json::json!({ "name": "To Revoke" }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify it's gone
    let (status, json) = get(
        state,
        "/xrpc/com.atproto.server.listAppPasswords",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["passwords"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_revoke_nonexistent_app_password() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.revokeAppPassword",
        &serde_json::json!({ "name": "Does Not Exist" }),
        Some(&token),
    )
    .await;

    // Should return an error for nonexistent password
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().is_some());
}

#[tokio::test]
async fn test_login_with_app_password() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Create an app password
    let (status, create_json) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "Login Test App" }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let app_password = create_json["password"].as_str().unwrap().to_string();

    // Login with app password using the handle
    let (status, session) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": app_password,
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["did"], TEST_DID);
    assert_eq!(session["handle"], TEST_HANDLE);
    assert!(session["accessJwt"].as_str().is_some());
    assert!(session["refreshJwt"].as_str().is_some());

    // Login with app password using the DID
    let (status, session) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_DID,
            "password": app_password,
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["did"], TEST_DID);
}

#[tokio::test]
async fn test_login_with_wrong_app_password() {
    let state = test_state();

    // Try to login with a fake app password
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": "fake-app-pass-word",
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["error"].as_str().is_some());
}

#[tokio::test]
async fn test_create_app_password_empty_name() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAppPassword",
        &serde_json::json!({ "name": "" }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().is_some());
}

// ==========================================================================
// updateHandle tests
// ==========================================================================

#[tokio::test]
async fn test_update_handle() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Update the handle
    let (status, _json) = post_json(
        state.clone(),
        "/xrpc/com.atproto.identity.updateHandle",
        &serde_json::json!({ "handle": "new.example.com" }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify the in-memory handle was updated
    assert_eq!(state.handle(), "new.example.com");

    // Verify the handle was persisted to the database
    let stored = state.storage.get_setting("handle").unwrap();
    assert_eq!(stored, Some("new.example.com".to_string()));

    // Verify resolveHandle now returns the new handle
    let (status, json) = get(
        state.clone(),
        "/xrpc/com.atproto.identity.resolveHandle?handle=new.example.com",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);

    // Verify getSession reflects the new handle
    let (status, json) = get(state, "/xrpc/com.atproto.server.getSession", Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["handle"], "new.example.com");
}

#[tokio::test]
async fn test_update_handle_no_change() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Update to the same handle — should be a no-op
    let (status, _json) = post_json(
        state,
        "/xrpc/com.atproto.identity.updateHandle",
        &serde_json::json!({ "handle": TEST_HANDLE }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_update_handle_invalid_format() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    // Invalid handle (no dot)
    let (status, json) = post_json(
        state.clone(),
        "/xrpc/com.atproto.identity.updateHandle",
        &serde_json::json!({ "handle": "nodothandle" }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().is_some());

    // Empty handle
    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.identity.updateHandle",
        &serde_json::json!({ "handle": "" }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"].as_str().is_some());
}

#[tokio::test]
async fn test_update_handle_requires_auth() {
    let state = test_state();

    let (status, _json) = post_json(
        state,
        "/xrpc/com.atproto.identity.updateHandle",
        &serde_json::json!({ "handle": "new.example.com" }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ============================================================================
// OAuth endpoint tests
// ============================================================================

/// Creates a test state with OAuth storage enabled.
fn test_state_with_oauth() -> Arc<AppState> {
    let storage = SqliteStorage::in_memory().expect("create test storage");
    let password_hash = cirrus_pds::auth::hash_password(TEST_PASSWORD).expect("hash password");
    let oauth_storage =
        cirrus_pds::oauth_storage::OAuthSqliteStorage::in_memory().expect("create oauth storage");

    Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: TEST_JWT_SECRET.to_vec(),
        password_hash: parking_lot::RwLock::new(password_hash),
        hostname: "test.example.com".to_string(),
        did: TEST_DID.to_string(),
        handle: parking_lot::RwLock::new(TEST_HANDLE.to_string()),
        public_key_multibase: "zQ3shtest123".to_string(),
        firehose: Firehose::new(),
        blob_store: Box::new(MemoryBlobStore::new()),
        handle_resolver: HandleResolver::new(),
        rate_limits: None,
        oauth_storage: Some(oauth_storage),
        signing_key: None,
        crawlers: None,
        appview: None,
    })
}

#[tokio::test]
async fn test_oauth_server_metadata() {
    let state = test_state();
    let app = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["issuer"], "https://test.example.com");
    assert_eq!(
        json["authorization_endpoint"],
        "https://test.example.com/oauth/authorize"
    );
    assert_eq!(
        json["token_endpoint"],
        "https://test.example.com/oauth/token"
    );
    assert_eq!(
        json["pushed_authorization_request_endpoint"],
        "https://test.example.com/oauth/par"
    );
    assert_eq!(
        json["revocation_endpoint"],
        "https://test.example.com/oauth/revoke"
    );
    assert!(json["require_pushed_authorization_requests"]
        .as_bool()
        .unwrap_or(false));
    assert!(json["scopes_supported"].as_array().is_some());
    assert!(json["code_challenge_methods_supported"]
        .as_array()
        .map_or(false, |a| a.iter().any(|v| v == "S256")));
}

#[tokio::test]
async fn test_oauth_par_success() {
    let state = test_state_with_oauth();
    let app = create_router(state);

    let body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&scope=atproto&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["request_uri"]
        .as_str()
        .unwrap()
        .starts_with("urn:ietf:params:oauth:request_uri:"));
    assert!(json["expires_in"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_oauth_par_missing_code_challenge() {
    let state = test_state_with_oauth();
    let app = create_router(state);

    let body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&scope=atproto&code_challenge_method=S256";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth_par_wrong_response_type() {
    let state = test_state_with_oauth();
    let app = create_router(state);

    let body = "response_type=token&client_id=did:web:example.com&redirect_uri=https://example.com/callback&code_challenge=abc&code_challenge_method=S256";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth_authorize_get_shows_consent_page() {
    let state = test_state_with_oauth();

    // First submit a PAR request to get a request_uri
    let app = create_router(Arc::clone(&state));
    let par_body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&scope=atproto&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(par_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap();

    // Now GET the consent page
    let app = create_router(Arc::clone(&state));
    let encoded_uri =
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/oauth/authorize?request_uri={encoded_uri}"))
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
    assert!(ct.contains("text/html"));

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(html.contains("Authorization Request"));
    assert!(html.contains("did:web:example.com"));
    assert!(html.contains("test.example.com"));
    assert!(html.contains("atproto"));
}

#[tokio::test]
async fn test_oauth_authorize_get_invalid_request_uri() {
    let state = test_state_with_oauth();
    let app = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/oauth/authorize?request_uri=invalid:uri")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_oauth_authorize_post_deny() {
    let state = test_state_with_oauth();

    // Submit PAR
    let app = create_router(Arc::clone(&state));
    let par_body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&scope=atproto&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256&state=mystate123";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(par_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap();

    // Deny the authorization
    let app = create_router(Arc::clone(&state));
    let form_body = format!(
        "request_uri={}&action=deny",
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://example.com/callback?"));
    assert!(location.contains("error=access_denied"));
    assert!(location.contains("state=mystate123"));
}

#[tokio::test]
async fn test_oauth_authorize_post_approve() {
    let state = test_state_with_oauth();

    // Submit PAR
    let app = create_router(Arc::clone(&state));
    let par_body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&scope=atproto&code_challenge=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk&code_challenge_method=S256&state=xyz";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(par_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap();

    // Approve the authorization
    let app = create_router(Arc::clone(&state));
    let form_body = format!(
        "request_uri={}&action=approve",
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://example.com/callback?"));
    assert!(location.contains("code="));
    assert!(location.contains("iss="));
    assert!(location.contains("state=xyz"));
}

#[tokio::test]
async fn test_oauth_token_exchange() {
    use cirrus_oauth::OAuthStorage;

    let state = test_state_with_oauth();
    let oauth_storage = state.oauth_storage.as_ref().unwrap();

    // Manually create an auth code (simulating the full flow)
    // Verifier must be >= 43 chars and only unreserved characters
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let code_challenge = cirrus_oauth::pkce::compute_s256_challenge(verifier);

    let auth_code = cirrus_oauth::tokens::AuthCodeData {
        code: "test-auth-code-123".to_string(),
        client_id: "did:web:example.com".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        code_challenge,
        scope: "atproto".to_string(),
        sub: TEST_DID.to_string(),
        expires_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300,
    };
    oauth_storage.save_auth_code(auth_code).await.unwrap();

    // Exchange code for tokens
    let app = create_router(Arc::clone(&state));
    let form_body = format!(
        "grant_type=authorization_code&code=test-auth-code-123&redirect_uri=https://example.com/callback&code_verifier={verifier}&client_id=did:web:example.com"
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["access_token"].as_str().is_some());
    assert!(json["refresh_token"].as_str().is_some());
    assert_eq!(json["token_type"], "DPoP");
    assert_eq!(json["sub"], TEST_DID);
    assert!(json["expires_in"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn test_oauth_token_invalid_code() {
    let state = test_state_with_oauth();
    let app = create_router(state);

    let form_body = "grant_type=authorization_code&code=nonexistent-code&redirect_uri=https://example.com/callback&code_verifier=test&client_id=did:web:example.com";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn test_oauth_revoke() {
    use cirrus_oauth::OAuthStorage;

    let state = test_state_with_oauth();
    let oauth_storage = state.oauth_storage.as_ref().unwrap();

    // Create a token directly
    let token =
        cirrus_oauth::tokens::create_tokens("did:web:example.com", TEST_DID, "atproto", None);
    let access_token = token.access_token.clone();
    oauth_storage.save_token(token).await.unwrap();

    // Verify token exists
    let t = oauth_storage
        .get_token_by_access(&access_token)
        .await
        .unwrap();
    assert!(t.is_some());
    assert!(!t.unwrap().revoked);

    // Revoke it
    let app = create_router(Arc::clone(&state));
    let form_body = format!("token={access_token}");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify it's revoked
    let t = oauth_storage
        .get_token_by_access(&access_token)
        .await
        .unwrap();
    assert!(t.unwrap().revoked);
}

#[tokio::test]
async fn test_oauth_endpoints_disabled_without_storage() {
    let state = test_state(); // No oauth_storage

    // PAR should return 501
    let app = create_router(Arc::clone(&state));
    let par_body = "response_type=code&client_id=did:web:example.com&redirect_uri=https://example.com/callback&code_challenge=abc&code_challenge_method=S256";

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(par_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

    // Token should return 501
    let app = create_router(Arc::clone(&state));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&code=x&redirect_uri=x&code_verifier=x&client_id=x",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

    // Revoke should return 501
    let app = create_router(Arc::clone(&state));
    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("token=abc"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn test_oauth_full_flow_par_through_token() {
    use cirrus_oauth::OAuthStorage;

    let state = test_state_with_oauth();

    // Step 1: PAR
    let app = create_router(Arc::clone(&state));
    let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-verifier";
    let code_challenge = {
        use sha2::Digest;
        let digest = sha2::Sha256::digest(code_verifier.as_bytes());
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, digest)
    };
    let par_body = format!(
        "response_type=code&client_id=did:web:app.example.com&redirect_uri=https://app.example.com/cb&scope=atproto&code_challenge={code_challenge}&code_challenge_method=S256&state=flowtest"
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/par")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(par_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let par_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par_json["request_uri"].as_str().unwrap().to_string();

    // Step 2: Approve consent
    let app = create_router(Arc::clone(&state));
    let form_body = format!(
        "request_uri={}&action=approve",
        url::form_urlencoded::byte_serialize(request_uri.as_bytes()).collect::<String>()
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/authorize")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.contains("code="));
    assert!(location.contains("state=flowtest"));

    // Extract the auth code from the redirect
    let code = url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.to_string())
        .unwrap();

    // Step 3: Exchange code for tokens
    let app = create_router(Arc::clone(&state));
    let token_body = format!(
        "grant_type=authorization_code&code={code}&redirect_uri=https://app.example.com/cb&code_verifier={code_verifier}&client_id=did:web:app.example.com"
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(token_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let token_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(token_json["access_token"].as_str().is_some());
    assert!(token_json["refresh_token"].as_str().is_some());
    assert_eq!(token_json["token_type"], "DPoP");
    assert_eq!(token_json["sub"], TEST_DID);
    assert_eq!(token_json["scope"], "atproto");

    // Step 4: Refresh token
    let refresh_token = token_json["refresh_token"].as_str().unwrap();
    let app = create_router(Arc::clone(&state));
    let refresh_body = format!("grant_type=refresh_token&refresh_token={refresh_token}");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(refresh_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let new_token: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(new_token["access_token"].as_str().is_some());
    assert_ne!(new_token["access_token"], token_json["access_token"]);

    // Step 5: Revoke the new token
    let new_access = new_token["access_token"].as_str().unwrap();
    let app = create_router(Arc::clone(&state));
    let revoke_body = format!("token={new_access}");

    let req = Request::builder()
        .method(Method::POST)
        .uri("/oauth/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(revoke_body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify token is revoked in storage
    let t = state
        .oauth_storage
        .as_ref()
        .unwrap()
        .get_token_by_access(new_access)
        .await
        .unwrap();
    assert!(t.unwrap().revoked);
}

// ============================================================================
// createAccount endpoint tests
// ============================================================================

/// Creates a test state with no password (simulates a fresh PDS awaiting createAccount).
fn test_state_fresh() -> Arc<AppState> {
    let storage = SqliteStorage::in_memory().expect("create test storage");

    Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: TEST_JWT_SECRET.to_vec(),
        password_hash: parking_lot::RwLock::new(String::new()),
        hostname: "test.example.com".to_string(),
        did: TEST_DID.to_string(),
        handle: parking_lot::RwLock::new(TEST_HANDLE.to_string()),
        public_key_multibase: "zQ3shtest123".to_string(),
        firehose: Firehose::new(),
        blob_store: Box::new(MemoryBlobStore::new()),
        handle_resolver: HandleResolver::new(),
        rate_limits: None,
        oauth_storage: None,
        signing_key: None,
        crawlers: None,
        appview: None,
    })
}

#[tokio::test]
async fn test_create_account_success() {
    let state = test_state_fresh();

    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": TEST_HANDLE,
            "password": "new-password-2024"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["did"], TEST_DID);
    assert_eq!(json["handle"], TEST_HANDLE);
    assert!(json["accessJwt"].as_str().is_some());
    assert!(json["refreshJwt"].as_str().is_some());

    // Password hash should now be set
    assert!(!state.password_hash().is_empty());

    // Should be able to create a session with the new password
    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": "new-password-2024"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(json["accessJwt"].as_str().is_some());
}

#[tokio::test]
async fn test_create_account_already_exists() {
    let state = test_state(); // Has password already set

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": TEST_HANDLE,
            "password": "another-password"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "AccountAlreadyExists");
}

#[tokio::test]
async fn test_create_account_empty_password() {
    let state = test_state_fresh();

    let (status, json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": TEST_HANDLE,
            "password": ""
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "InvalidRequest");
}

#[tokio::test]
async fn test_create_account_invalid_handle() {
    let state = test_state_fresh();

    let (status, _json) = post_json(
        state,
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": "not a valid handle!",
            "password": "test-password"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_account_updates_handle() {
    let state = test_state_fresh();

    // Create account with a different handle than preconfigured
    let (status, json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": "new-handle.example.com",
            "password": "test-password-2024"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["handle"], "new-handle.example.com");

    // In-memory handle should be updated
    assert_eq!(state.handle(), "new-handle.example.com");

    // Persisted handle should be updated too
    let stored_handle = state.storage.get_setting("handle").unwrap();
    assert_eq!(stored_handle, Some("new-handle.example.com".to_string()));
}

#[tokio::test]
async fn test_create_account_persists_password_hash() {
    let state = test_state_fresh();

    let (status, _json) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.server.createAccount",
        &serde_json::json!({
            "handle": TEST_HANDLE,
            "password": "persisted-password"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Password hash should be persisted in settings
    let stored_hash = state.storage.get_setting("password_hash").unwrap();
    assert!(stored_hash.is_some());
    assert!(stored_hash.unwrap().starts_with("$2")); // bcrypt prefix
}

// ============================================================================
// PLC operation endpoint tests
// ============================================================================

#[tokio::test]
async fn test_get_recommended_did_credentials() {
    let state = test_state_with_signing_key();
    let (status, body) = get(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Should contain alsoKnownAs with the handle
    let also_known_as = body["alsoKnownAs"].as_array().unwrap();
    assert_eq!(also_known_as.len(), 1);
    assert!(also_known_as[0].as_str().unwrap().contains(TEST_HANDLE));
    // Should contain verificationMethods with atproto key
    assert!(body["verificationMethods"]["atproto"].is_string());
    // Should contain services with PDS endpoint
    assert_eq!(
        body["services"]["atproto_pds"]["type"].as_str().unwrap(),
        "AtprotoPersonalDataServer"
    );
    // Should contain rotationKeys when signing key is configured
    assert!(body["rotationKeys"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_get_recommended_did_credentials_no_signing_key() {
    let state = test_state();
    let (status, body) = get(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.getRecommendedDidCredentials",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Without signing key, rotationKeys should be null
    assert!(body["rotationKeys"].is_null());
    // Other fields should still be present
    assert!(body["alsoKnownAs"].is_array());
    assert!(body["verificationMethods"].is_object());
    assert!(body["services"].is_object());
}

#[tokio::test]
async fn test_request_plc_operation_signature() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, _body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Token should be stored in settings
    let stored = state.storage.get_setting("plc_operation_token").unwrap();
    assert!(stored.is_some());
    let token_data: serde_json::Value = serde_json::from_str(&stored.unwrap()).unwrap();
    assert!(token_data["token"].is_string());
    assert!(token_data["expires_at"].is_u64());
}

#[tokio::test]
async fn test_request_plc_operation_signature_requires_auth() {
    let state = test_state_with_signing_key();

    let (status, _body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        &serde_json::json!({}),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_sign_plc_operation_with_token() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    // First, request a PLC operation token
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Retrieve the token from settings
    let stored = state
        .storage
        .get_setting("plc_operation_token")
        .unwrap()
        .unwrap();
    let token_data: serde_json::Value = serde_json::from_str(&stored).unwrap();
    let plc_token = token_data["token"].as_str().unwrap();

    // Sign the operation with the token
    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.signPlcOperation",
        &serde_json::json!({
            "token": plc_token,
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Response should contain a signed operation
    let operation = &body["operation"];
    assert!(operation["sig"].is_string());
    assert_eq!(operation["type"].as_str().unwrap(), "plc_operation");
    assert!(operation["rotationKeys"].is_array());
    assert!(operation["alsoKnownAs"].is_array());
    assert!(operation["verificationMethods"].is_object());
    assert!(operation["services"].is_object());

    // Token should be consumed (cleared)
    let stored_after = state
        .storage
        .get_setting("plc_operation_token")
        .unwrap()
        .unwrap();
    assert!(stored_after.is_empty());
}

#[tokio::test]
async fn test_sign_plc_operation_without_token() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    // Sign without providing a PLC token (allowed — token is optional)
    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.signPlcOperation",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let operation = &body["operation"];
    assert!(operation["sig"].is_string());
    assert_eq!(operation["type"].as_str().unwrap(), "plc_operation");
}

#[tokio::test]
async fn test_sign_plc_operation_invalid_token() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    // Request a valid token first
    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.requestPlcOperationSignature",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Try signing with wrong token
    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.signPlcOperation",
        &serde_json::json!({
            "token": "wrong-token-value",
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "InvalidToken");
}

#[tokio::test]
async fn test_sign_plc_operation_no_signing_key() {
    let state = test_state(); // No signing key
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.signPlcOperation",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"].as_str().unwrap(), "InternalError");
}

#[tokio::test]
async fn test_sign_plc_operation_custom_overrides() {
    let state = test_state_with_signing_key();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.signPlcOperation",
        &serde_json::json!({
            "alsoKnownAs": ["at://custom.handle.example"],
            "services": {
                "atproto_pds": {
                    "type": "AtprotoPersonalDataServer",
                    "endpoint": "https://custom-pds.example.com"
                }
            }
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let operation = &body["operation"];
    // Custom overrides should be reflected
    let aka = operation["alsoKnownAs"].as_array().unwrap();
    assert_eq!(aka[0].as_str().unwrap(), "at://custom.handle.example");
    let endpoint = operation["services"]["atproto_pds"]["endpoint"]
        .as_str()
        .unwrap();
    assert_eq!(endpoint, "https://custom-pds.example.com");
}

#[tokio::test]
async fn test_submit_plc_operation_missing_signature() {
    let state = test_state();

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.identity.submitPlcOperation",
        &serde_json::json!({
            "operation": {
                "type": "plc_operation",
                "rotationKeys": [],
                "alsoKnownAs": [],
                "verificationMethods": {},
                "services": {}
            }
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"].as_str().unwrap().contains("signed"));
}

// ============================================================================
// Moderation report tests
// ============================================================================

#[tokio::test]
async fn test_create_report_success() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &serde_json::json!({
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "reason": "This is spam content",
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:spammer123"
            }
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"].as_i64().unwrap(), 1);
    assert_eq!(
        body["reasonType"].as_str().unwrap(),
        "com.atproto.moderation.defs#reasonSpam"
    );
    assert_eq!(body["reason"].as_str().unwrap(), "This is spam content");
    assert_eq!(body["reportedBy"].as_str().unwrap(), TEST_DID);
    assert!(body["createdAt"].is_string());
}

#[tokio::test]
async fn test_create_report_increments_id() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let report = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": "did:plc:test"
        }
    });

    let (status, body1) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &report,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body2) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &report,
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(body1["id"].as_i64().unwrap(), 1);
    assert_eq!(body2["id"].as_i64().unwrap(), 2);
}

#[tokio::test]
async fn test_create_report_invalid_reason_type() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &serde_json::json!({
            "reasonType": "invalid.reason.type",
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:test"
            }
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("invalid reasonType"));
}

#[tokio::test]
async fn test_create_report_requires_auth() {
    let state = test_state();

    let (status, _) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &serde_json::json!({
            "reasonType": "com.atproto.moderation.defs#reasonSpam",
            "subject": {
                "$type": "com.atproto.admin.defs#repoRef",
                "did": "did:plc:test"
            }
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_report_record_subject() {
    let state = test_state();
    let token = get_access_token(Arc::clone(&state)).await;

    let (status, body) = post_json(
        Arc::clone(&state),
        "/xrpc/com.atproto.moderation.createReport",
        &serde_json::json!({
            "reasonType": "com.atproto.moderation.defs#reasonViolation",
            "subject": {
                "$type": "com.atproto.repo.strongRef",
                "uri": "at://did:plc:bad/app.bsky.feed.post/abc123",
                "cid": "bafyreicid"
            }
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["subject"]["uri"].as_str().unwrap(),
        "at://did:plc:bad/app.bsky.feed.post/abc123"
    );
}

// ==========================================================================
// Email endpoint tests
// ==========================================================================

#[tokio::test]
async fn test_request_email_confirmation_requires_auth() {
    let state = test_state();
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        &serde_json::json!({}),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_email_confirmation_success() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestEmailConfirmation",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_confirm_email_with_valid_token() {
    let state = test_state();
    let access_token = get_access_token(state.clone()).await;

    // Create an email confirmation token directly
    let email_token = state
        .storage
        .create_email_token(TEST_DID, "confirm_email")
        .expect("create token");

    let (status, _body) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.confirmEmail",
        &serde_json::json!({
            "email": "user@example.com",
            "token": email_token
        }),
        Some(&access_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Verify email was stored
    let stored = state.storage.get_setting("email").unwrap();
    assert_eq!(stored.as_deref(), Some("user@example.com"));
    let confirmed = state.storage.get_setting("email_confirmed").unwrap();
    assert_eq!(confirmed.as_deref(), Some("true"));
}

#[tokio::test]
async fn test_confirm_email_invalid_token() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.confirmEmail",
        &serde_json::json!({
            "email": "user@example.com",
            "token": "invalid-token-value"
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "ExpiredToken");
}

#[tokio::test]
async fn test_request_password_reset_always_ok() {
    let state = test_state();

    // Password reset is unauthenticated and always returns OK
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestPasswordReset",
        &serde_json::json!({
            "email": "user@example.com"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_reset_password_with_valid_token() {
    let state = test_state();

    // Create a reset token directly
    let reset_token = state
        .storage
        .create_email_token(TEST_DID, "reset_password")
        .expect("create token");

    let (status, _body) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.resetPassword",
        &serde_json::json!({
            "token": reset_token,
            "password": "new-secure-password-2024"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Verify old password no longer works
    let (status, _body) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": TEST_PASSWORD
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Verify new password works
    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": "new-secure-password-2024"
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["accessJwt"].as_str().is_some());
}

#[tokio::test]
async fn test_reset_password_invalid_token() {
    let state = test_state();

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.resetPassword",
        &serde_json::json!({
            "token": "bad-token",
            "password": "new-password"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "ExpiredToken");
}

#[tokio::test]
async fn test_request_email_update_requires_auth() {
    let state = test_state();
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestEmailUpdate",
        &serde_json::json!({}),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_email_update_returns_token_required() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestEmailUpdate",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tokenRequired"].as_bool().unwrap(), true);
}

#[tokio::test]
async fn test_update_email_with_valid_token() {
    let state = test_state();
    let access_token = get_access_token(state.clone()).await;

    // Set initial email
    state
        .storage
        .put_setting("email", "old@example.com")
        .unwrap();
    state
        .storage
        .put_setting("email_confirmed", "true")
        .unwrap();

    // Create an update token
    let email_token = state
        .storage
        .create_email_token(TEST_DID, "update_email")
        .expect("create token");

    let (status, _body) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.updateEmail",
        &serde_json::json!({
            "email": "new@example.com",
            "token": email_token
        }),
        Some(&access_token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Verify email was updated
    let stored = state.storage.get_setting("email").unwrap();
    assert_eq!(stored.as_deref(), Some("new@example.com"));
    // New email should be unconfirmed
    let confirmed = state.storage.get_setting("email_confirmed").unwrap();
    assert_eq!(confirmed.as_deref(), Some("false"));
}

#[tokio::test]
async fn test_update_email_invalid_token() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.updateEmail",
        &serde_json::json!({
            "email": "new@example.com",
            "token": "invalid-token"
        }),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "ExpiredToken");
}

// ==========================================================================
// Account deletion tests
// ==========================================================================

#[tokio::test]
async fn test_request_account_delete_requires_auth() {
    let state = test_state();
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestAccountDelete",
        &serde_json::json!({}),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_request_account_delete_success() {
    let state = test_state();
    let token = get_access_token(state.clone()).await;
    let (status, _body) = post_json(
        state,
        "/xrpc/com.atproto.server.requestAccountDelete",
        &serde_json::json!({}),
        Some(&token),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_delete_account_wrong_did() {
    let state = test_state();
    let delete_token = state
        .storage
        .create_email_token(TEST_DID, "delete_account")
        .unwrap();

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.deleteAccount",
        &serde_json::json!({
            "did": "did:plc:wrong",
            "password": TEST_PASSWORD,
            "token": delete_token
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "InvalidRequest");
}

#[tokio::test]
async fn test_delete_account_wrong_password() {
    let state = test_state();
    let delete_token = state
        .storage
        .create_email_token(TEST_DID, "delete_account")
        .unwrap();

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.deleteAccount",
        &serde_json::json!({
            "did": TEST_DID,
            "password": "wrong-password",
            "token": delete_token
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"].as_str().unwrap(), "AuthenticationRequired");
}

#[tokio::test]
async fn test_delete_account_invalid_token() {
    let state = test_state();

    let (status, body) = post_json(
        state,
        "/xrpc/com.atproto.server.deleteAccount",
        &serde_json::json!({
            "did": TEST_DID,
            "password": TEST_PASSWORD,
            "token": "invalid-token"
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"].as_str().unwrap(), "ExpiredToken");
}

#[tokio::test]
async fn test_delete_account_success() {
    let state = test_state();

    // First create a record to verify data exists
    let token = get_access_token(state.clone()).await;
    let (status, _) = post_json(
        state.clone(),
        "/xrpc/com.atproto.repo.createRecord",
        &serde_json::json!({
            "repo": TEST_DID,
            "collection": "app.bsky.feed.post",
            "record": {
                "$type": "app.bsky.feed.post",
                "text": "test post",
                "createdAt": "2024-01-01T00:00:00Z"
            }
        }),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Create deletion token
    let delete_token = state
        .storage
        .create_email_token(TEST_DID, "delete_account")
        .unwrap();

    // Delete the account
    let (status, _body) = post_json(
        state.clone(),
        "/xrpc/com.atproto.server.deleteAccount",
        &serde_json::json!({
            "did": TEST_DID,
            "password": TEST_PASSWORD,
            "token": delete_token
        }),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // Login should no longer work (password hash cleared)
    let (status, _) = post_json(
        state,
        "/xrpc/com.atproto.server.createSession",
        &serde_json::json!({
            "identifier": TEST_HANDLE,
            "password": TEST_PASSWORD
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
