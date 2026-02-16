//! Axum middleware and extractors for authentication.

use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::AUTHORIZATION, request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cirrus_common::jwt::{get_algorithm, verify_hs256, Claims};

use crate::auth::{AuthContext, AuthMethod};
use crate::routes::AppState;
use crate::xrpc::XrpcError;

/// Extractor for optional authentication.
///
/// Use this for endpoints that work with or without auth,
/// but may behave differently based on auth status.
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<AuthContext>);

/// Extractor for required authentication.
///
/// Use this for endpoints that require authentication.
/// Returns 401 Unauthorized if no valid auth is provided.
#[derive(Debug, Clone)]
pub struct RequireAuth(pub AuthContext);

/// Extractor for admin authentication.
///
/// Requires authentication and verifies the DID matches the PDS owner.
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub AuthContext);

/// Authentication error returned when auth fails.
#[derive(Debug)]
pub struct AuthError {
    message: String,
    status: StatusCode,
}

impl AuthError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::UNAUTHORIZED,
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: StatusCode::FORBIDDEN,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let error = XrpcError::auth_required(self.message);
        (self.status, Json(error)).into_response()
    }
}

/// Extracts and verifies authentication from request headers.
///
/// Supports three auth schemes:
/// - `Bearer <jwt>` with HS256 (session JWT)
/// - `Bearer <jwt>` with ES256K (service JWT)
/// - `DPoP <token>` with a DPoP proof header (OAuth 2.1 DPoP-bound token)
fn extract_auth(parts: &Parts, state: &AppState) -> Result<AuthContext, AuthError> {
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::unauthorized("missing authorization header"))?;

    // Check for DPoP scheme first
    if let Some(access_token) = auth_header.strip_prefix("DPoP ") {
        return extract_dpop_auth(parts, state, access_token);
    }

    // Fall back to Bearer scheme
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| AuthError::unauthorized("invalid authorization format"))?;

    // Check the algorithm to determine auth type
    let alg = get_algorithm(token)
        .map_err(|e| AuthError::unauthorized(format!("invalid token: {e}")))?;

    match alg.as_str() {
        "HS256" => {
            // Session JWT - verify with symmetric secret
            let claims: Claims = verify_hs256(token, &state.jwt_secret)
                .map_err(|e| AuthError::unauthorized(format!("invalid session token: {e}")))?;

            // Check expiration is handled by verify_hs256
            let did = claims.sub.unwrap_or(claims.iss);
            let scope = claims.scope.unwrap_or_else(|| "atproto".to_string());

            Ok(AuthContext {
                did,
                scope,
                method: AuthMethod::SessionJwt,
            })
        }
        "ES256K" => {
            // Service JWT - need to verify with public key from DID document
            // For now, decode without full verification (would need async DID resolution)
            let claims: Claims = cirrus_common::jwt::decode_unverified(token)
                .map_err(|e| AuthError::unauthorized(format!("invalid service token: {e}")))?;

            if claims.is_expired() {
                return Err(AuthError::unauthorized("token expired"));
            }

            let did = claims.sub.unwrap_or(claims.iss);
            let scope = claims.scope.unwrap_or_else(|| "atproto".to_string());

            Ok(AuthContext {
                did,
                scope,
                method: AuthMethod::ServiceJwt,
            })
        }
        other => Err(AuthError::unauthorized(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}

/// Verifies DPoP-bound OAuth authentication (RFC 9449).
///
/// Validates the DPoP proof JWT from the `DPoP` header, then looks up
/// the access token in OAuth storage to verify the key binding (`dpop_jkt`).
fn extract_dpop_auth(
    parts: &Parts,
    state: &AppState,
    access_token: &str,
) -> Result<AuthContext, AuthError> {
    // Get the DPoP proof from the DPoP header
    let dpop_proof = parts
        .headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::unauthorized("missing DPoP proof header"))?;

    // Get OAuth storage
    let oauth_storage = state
        .oauth_storage
        .as_ref()
        .ok_or_else(|| AuthError::unauthorized("OAuth not configured"))?;

    // Reconstruct the full request URI for DPoP verification
    let method = parts.method.as_str();
    let uri = format!("https://{}{}", state.hostname, parts.uri.path());

    // Verify the DPoP proof (checks signature, method, URI, access token hash, timing)
    let jwk = cirrus_oauth::dpop::verify_proof(
        dpop_proof,
        method,
        &uri,
        Some(access_token),
        None,
    )
    .map_err(|e| AuthError::unauthorized(format!("DPoP proof invalid: {e}")))?;

    // Compute the JWK thumbprint from the proof's public key
    let thumbprint = cirrus_oauth::dpop::compute_jwk_thumbprint(&jwk);

    // Look up the access token in OAuth storage
    let token_data = oauth_storage
        .get_token_sync(access_token)
        .ok_or_else(|| AuthError::unauthorized("unknown access token"))?;

    // Verify token is valid (not expired, not revoked)
    if !token_data.is_valid() {
        return Err(AuthError::unauthorized("token expired or revoked"));
    }

    // Verify the DPoP key binding matches
    match &token_data.dpop_jkt {
        Some(jkt) if jkt == &thumbprint => {}
        Some(_) => {
            return Err(AuthError::unauthorized("DPoP key binding mismatch"));
        }
        None => {
            return Err(AuthError::unauthorized(
                "token not bound to a DPoP key",
            ));
        }
    }

    Ok(AuthContext {
        did: token_data.sub,
        scope: token_data.scope,
        method: AuthMethod::DpopOAuth,
    })
}

/// Extracts authentication without scope restrictions.
///
/// Used by `refresh_session` which needs to accept refresh-scoped tokens.
/// All other endpoints should use `RequireAuth` or `RequireAdmin` extractors
/// which reject refresh tokens.
pub fn extract_auth_for_refresh(
    parts: &Parts,
    state: &AppState,
) -> Result<AuthContext, AuthError> {
    extract_auth(parts, state)
}

impl<S> FromRequestParts<S> for OptionalAuth
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);
        let auth = extract_auth(parts, &app_state).ok();
        Ok(Self(auth))
    }
}

impl<S> FromRequestParts<S> for RequireAuth
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);
        let auth = extract_auth(parts, &app_state)?;

        // Reject refresh tokens — they may only be used for refreshSession
        if auth.scope == "atproto:refresh" {
            return Err(AuthError::unauthorized(
                "refresh token cannot be used for this endpoint",
            ));
        }

        Ok(Self(auth))
    }
}

impl<S> FromRequestParts<S> for RequireAdmin
where
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);
        let auth = extract_auth(parts, &app_state)?;

        // Reject refresh tokens — they may only be used for refreshSession
        if auth.scope == "atproto:refresh" {
            return Err(AuthError::unauthorized(
                "refresh token cannot be used for this endpoint",
            ));
        }

        // Verify the authenticated DID is the PDS owner
        if auth.did != app_state.did {
            return Err(AuthError::forbidden("not authorized for this PDS"));
        }

        Ok(Self(auth))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_error_response() {
        let error = AuthError::unauthorized("test error");
        assert_eq!(error.status, StatusCode::UNAUTHORIZED);

        let error = AuthError::forbidden("forbidden");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    /// Helper to build a minimal `AppState` with OAuth storage for tests.
    fn test_state_with_oauth() -> AppState {
        let storage = crate::storage::SqliteStorage::in_memory()
            .expect("failed to create test storage");
        let oauth_storage = crate::oauth_storage::OAuthSqliteStorage::in_memory()
            .expect("failed to create test oauth storage");

        AppState {
            storage,
            lexicons: crate::lexicon::LexiconStore::new(),
            jwt_secret: b"test-secret-key-for-jwt".to_vec(),
            password_hash: String::new(),
            hostname: "pds.example.com".to_string(),
            did: "did:plc:testuser".to_string(),
            handle: "test.example.com".to_string(),
            public_key_multibase: String::new(),
            firehose: crate::sequencer::Firehose::new(),
            blob_store: Box::new(crate::blobs::MemoryBlobStore::new()),
            handle_resolver: crate::handle::HandleResolver::new(),
            rate_limits: None,
            oauth_storage: Some(oauth_storage),
            signing_key: None,
        }
    }

    /// Helper to build request Parts with given headers.
    fn make_parts(method: &str, uri: &str, headers: Vec<(&str, &str)>) -> Parts {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(uri);
        for (key, value) in headers {
            builder = builder.header(key, value);
        }
        let (parts, _body) = builder
            .body(())
            .expect("failed to build request")
            .into_parts();
        parts
    }

    #[test]
    fn test_dpop_auth_missing_proof_header() {
        let state = test_state_with_oauth();
        let parts = make_parts(
            "GET",
            "/xrpc/com.atproto.repo.listRecords",
            vec![("authorization", "DPoP some-token")],
        );

        let result = extract_auth(&parts, &state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert!(err.message.contains("missing DPoP proof header"));
    }

    #[test]
    fn test_dpop_auth_oauth_not_configured() {
        let mut state = test_state_with_oauth();
        state.oauth_storage = None;

        let parts = make_parts(
            "GET",
            "/xrpc/com.atproto.repo.listRecords",
            vec![
                ("authorization", "DPoP some-token"),
                ("dpop", "fake.proof.jwt"),
            ],
        );

        let result = extract_auth(&parts, &state);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("OAuth not configured"));
    }

    #[tokio::test]
    async fn test_dpop_auth_full_flow() {
        use cirrus_oauth::dpop::{DpopKeyPair, compute_jwk_thumbprint};
        use cirrus_oauth::storage::OAuthStorage;
        use cirrus_oauth::tokens::TokenData;

        let state = test_state_with_oauth();
        let oauth = state.oauth_storage.as_ref().expect("oauth configured");

        // Generate a DPoP key pair
        let keypair = DpopKeyPair::generate();
        let thumbprint = compute_jwk_thumbprint(&keypair.public_jwk());

        // Store a token bound to this key
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let token_data = TokenData {
            access_token: "dpop-access-token-123".to_string(),
            refresh_token: "dpop-refresh-token-456".to_string(),
            client_id: "did:web:client.example.com".to_string(),
            sub: "did:plc:testuser".to_string(),
            scope: "atproto".to_string(),
            dpop_jkt: Some(thumbprint),
            issued_at: now,
            expires_at: now + 3600,
            revoked: false,
        };
        oauth.save_token(token_data).await.expect("save token");

        // Create a DPoP proof for this request
        let proof = keypair
            .create_proof(
                "GET",
                "https://pds.example.com/xrpc/com.atproto.repo.listRecords",
                Some("dpop-access-token-123"),
                None,
            )
            .expect("create proof");

        let parts = make_parts(
            "GET",
            "/xrpc/com.atproto.repo.listRecords",
            vec![
                ("authorization", "DPoP dpop-access-token-123"),
                ("dpop", &proof),
            ],
        );

        let result = extract_auth(&parts, &state);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        let auth = result.expect("auth should succeed");
        assert_eq!(auth.did, "did:plc:testuser");
        assert_eq!(auth.scope, "atproto");
        assert_eq!(auth.method, AuthMethod::DpopOAuth);
    }

    #[tokio::test]
    async fn test_dpop_auth_key_mismatch() {
        use cirrus_oauth::dpop::DpopKeyPair;
        use cirrus_oauth::storage::OAuthStorage;
        use cirrus_oauth::tokens::TokenData;

        let state = test_state_with_oauth();
        let oauth = state.oauth_storage.as_ref().expect("oauth configured");

        // Store a token with one key thumbprint
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let token_data = TokenData {
            access_token: "dpop-token-mismatch".to_string(),
            refresh_token: "dpop-refresh-mismatch".to_string(),
            client_id: "did:web:client.example.com".to_string(),
            sub: "did:plc:testuser".to_string(),
            scope: "atproto".to_string(),
            dpop_jkt: Some("wrong-thumbprint".to_string()),
            issued_at: now,
            expires_at: now + 3600,
            revoked: false,
        };
        oauth.save_token(token_data).await.expect("save token");

        // Create proof with a different key
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof(
                "GET",
                "https://pds.example.com/xrpc/test",
                Some("dpop-token-mismatch"),
                None,
            )
            .expect("create proof");

        let parts = make_parts(
            "GET",
            "/xrpc/test",
            vec![
                ("authorization", "DPoP dpop-token-mismatch"),
                ("dpop", &proof),
            ],
        );

        let result = extract_auth(&parts, &state);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("key binding mismatch"));
    }

    #[tokio::test]
    async fn test_dpop_auth_revoked_token() {
        use cirrus_oauth::dpop::{DpopKeyPair, compute_jwk_thumbprint};
        use cirrus_oauth::storage::OAuthStorage;
        use cirrus_oauth::tokens::TokenData;

        let state = test_state_with_oauth();
        let oauth = state.oauth_storage.as_ref().expect("oauth configured");

        let keypair = DpopKeyPair::generate();
        let thumbprint = compute_jwk_thumbprint(&keypair.public_jwk());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let token_data = TokenData {
            access_token: "dpop-revoked-token".to_string(),
            refresh_token: "dpop-revoked-refresh".to_string(),
            client_id: "did:web:client.example.com".to_string(),
            sub: "did:plc:testuser".to_string(),
            scope: "atproto".to_string(),
            dpop_jkt: Some(thumbprint),
            issued_at: now,
            expires_at: now + 3600,
            revoked: true,
        };
        oauth.save_token(token_data).await.expect("save token");

        let proof = keypair
            .create_proof(
                "GET",
                "https://pds.example.com/xrpc/test",
                Some("dpop-revoked-token"),
                None,
            )
            .expect("create proof");

        let parts = make_parts(
            "GET",
            "/xrpc/test",
            vec![
                ("authorization", "DPoP dpop-revoked-token"),
                ("dpop", &proof),
            ],
        );

        let result = extract_auth(&parts, &state);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("expired or revoked"));
    }
}
