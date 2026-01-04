//! PAR (Pushed Authorization Requests) implementation.
//!
//! Implements RFC 9126 for secure authorization request submission.

use serde::{Deserialize, Serialize};

use crate::error::{OAuthError, Result};

/// PAR request expiration time in seconds.
const PAR_REQUEST_LIFETIME_SECS: u64 = 90;

/// Prefix for PAR request URIs.
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// PAR request data stored server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParRequest {
    /// The client ID that submitted the request.
    pub client_id: String,
    /// The redirect URI for the authorization response.
    pub redirect_uri: String,
    /// The requested scope.
    pub scope: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method (always S256).
    pub code_challenge_method: String,
    /// Optional state parameter.
    pub state: Option<String>,
    /// Optional nonce for `OpenID` Connect.
    pub nonce: Option<String>,
    /// When the request expires (Unix timestamp).
    pub expires_at: u64,
}

impl ParRequest {
    /// Creates a new PAR request with default expiration.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        code_challenge: impl Into<String>,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            code_challenge: code_challenge.into(),
            code_challenge_method: "S256".to_string(),
            state: None,
            nonce: None,
            expires_at: now + PAR_REQUEST_LIFETIME_SECS,
        }
    }

    /// Sets the state parameter.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Sets the nonce parameter.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Checks if the request has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at < now
    }
}

/// Generates a unique request URI for a PAR request.
#[must_use]
pub fn generate_request_uri() -> String {
    let id = uuid::Uuid::new_v4();
    format!("{REQUEST_URI_PREFIX}{id}")
}

/// Validates a request URI format.
///
/// # Errors
/// Returns an error if the URI format is invalid.
pub fn validate_request_uri(uri: &str) -> Result<&str> {
    uri.strip_prefix(REQUEST_URI_PREFIX)
        .ok_or_else(|| OAuthError::InvalidRequest("invalid request_uri format".into()))
}

/// PAR response returned to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParResponse {
    /// The request URI to use in the authorization request.
    pub request_uri: String,
    /// Lifetime of the request URI in seconds.
    pub expires_in: u64,
}

impl ParResponse {
    /// Creates a new PAR response.
    #[must_use]
    pub const fn new(request_uri: String) -> Self {
        Self {
            request_uri,
            expires_in: PAR_REQUEST_LIFETIME_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_par_request_creation() {
        let request = ParRequest::new(
            "client123",
            "https://example.com/callback",
            "atproto",
            "challenge123",
        );

        assert_eq!(request.client_id, "client123");
        assert_eq!(request.code_challenge_method, "S256");
        assert!(!request.is_expired());
    }

    #[test]
    fn test_par_request_with_state() {
        let request = ParRequest::new("client", "https://example.com", "scope", "challenge")
            .with_state("state123")
            .with_nonce("nonce456");

        assert_eq!(request.state, Some("state123".to_string()));
        assert_eq!(request.nonce, Some("nonce456".to_string()));
    }

    #[test]
    fn test_generate_request_uri() {
        let uri1 = generate_request_uri();
        let uri2 = generate_request_uri();

        assert!(uri1.starts_with(REQUEST_URI_PREFIX));
        assert!(uri2.starts_with(REQUEST_URI_PREFIX));
        assert_ne!(uri1, uri2);
    }

    #[test]
    fn test_validate_request_uri() {
        let uri = generate_request_uri();
        assert!(validate_request_uri(&uri).is_ok());

        assert!(validate_request_uri("invalid:uri").is_err());
    }

    #[test]
    fn test_par_response() {
        let response = ParResponse::new("urn:ietf:params:oauth:request_uri:abc".to_string());

        assert_eq!(response.expires_in, PAR_REQUEST_LIFETIME_SECS);
    }
}
