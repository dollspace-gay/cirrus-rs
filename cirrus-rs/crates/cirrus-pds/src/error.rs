//! PDS error types.

use thiserror::Error;

/// Result type alias for PDS operations.
pub type Result<T> = std::result::Result<T, PdsError>;

/// PDS-specific errors.
#[derive(Debug, Error)]
pub enum PdsError {
    /// Repository not found.
    #[error("repo not found: {0}")]
    RepoNotFound(String),

    /// Record not found.
    #[error("record not found: {0}")]
    RecordNotFound(String),

    /// Invalid record data.
    #[error("invalid record: {0}")]
    InvalidRecord(String),

    /// Authentication failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Authorization denied.
    #[error("not authorized: {0}")]
    NotAuthorized(String),

    /// Account is deactivated.
    #[error("account deactivated")]
    AccountDeactivated,

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// DID resolution failed.
    #[error("DID resolution failed: {0}")]
    DidResolution(String),

    /// Handle resolution failed.
    #[error("handle resolution failed: {0}")]
    HandleResolution(String),

    /// Blob storage error.
    #[error("blob error: {0}")]
    Blob(String),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// Lexicon error.
    #[error("lexicon error: {0}")]
    Lexicon(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Common error.
    #[error(transparent)]
    Common(#[from] cirrus_common::Error),

    /// OAuth error.
    #[error(transparent)]
    OAuth(#[from] cirrus_oauth::OAuthError),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// HTTP error.
    #[error("HTTP error: {0}")]
    Http(String),

    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<rusqlite::Error> for PdsError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}
