//! OAuth error types.

use thiserror::Error;

/// Result type alias for OAuth operations.
pub type Result<T> = std::result::Result<T, OAuthError>;

/// OAuth-specific errors.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// Invalid client configuration.
    #[error("invalid_client: {0}")]
    InvalidClient(String),

    /// Invalid request parameters.
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// Invalid authorization code.
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    /// Invalid scope requested.
    #[error("invalid_scope: {0}")]
    InvalidScope(String),

    /// Unauthorized client for this operation.
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),

    /// Access denied by user or policy.
    #[error("access_denied: {0}")]
    AccessDenied(String),

    /// Server error during processing.
    #[error("server_error: {0}")]
    ServerError(String),

    /// PKCE verification failed.
    #[error("PKCE verification failed: {0}")]
    PkceError(String),

    /// `DPoP` verification failed.
    #[error("DPoP error: {0}")]
    DpopError(String),

    /// Token has expired.
    #[error("token expired")]
    TokenExpired,

    /// Token has been revoked.
    #[error("token revoked")]
    TokenRevoked,

    /// Storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),

    /// HTTP client error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// Common error from cirrus-common.
    #[error(transparent)]
    Common(#[from] cirrus_common::Error),
}
