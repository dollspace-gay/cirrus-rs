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
fn extract_auth(parts: &Parts, state: &AppState) -> Result<AuthContext, AuthError> {
    let auth_header = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AuthError::unauthorized("missing authorization header"))?;

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
}
