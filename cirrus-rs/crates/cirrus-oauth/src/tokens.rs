//! OAuth token generation and management.

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// Access token lifetime in seconds (1 hour).
pub const ACCESS_TOKEN_LIFETIME_SECS: u64 = 3600;

/// Refresh token lifetime in seconds (90 days).
pub const REFRESH_TOKEN_LIFETIME_SECS: u64 = 90 * 24 * 3600;

/// Authorization code lifetime in seconds (5 minutes).
pub const AUTH_CODE_LIFETIME_SECS: u64 = 300;

/// Token data stored server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenData {
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: String,
    /// Client ID the token was issued to.
    pub client_id: String,
    /// Subject (user DID).
    pub sub: String,
    /// Granted scope.
    pub scope: String,
    /// `DPoP` key thumbprint (if DPoP-bound).
    pub dpop_jkt: Option<String>,
    /// When the token was issued (Unix timestamp).
    pub issued_at: u64,
    /// When the access token expires (Unix timestamp).
    pub expires_at: u64,
    /// Whether the token has been revoked.
    pub revoked: bool,
}

impl TokenData {
    /// Checks if the access token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at < now
    }

    /// Checks if the token is valid (not expired and not revoked).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.is_expired()
    }
}

/// Authorization code data stored server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeData {
    /// The authorization code.
    pub code: String,
    /// Client ID the code was issued to.
    pub client_id: String,
    /// Redirect URI used in the authorization request.
    pub redirect_uri: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// Granted scope.
    pub scope: String,
    /// Subject (user DID).
    pub sub: String,
    /// When the code expires (Unix timestamp).
    pub expires_at: u64,
}

impl AuthCodeData {
    /// Checks if the authorization code has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.expires_at < now
    }
}

/// Generates a random authorization code.
#[must_use]
pub fn generate_auth_code() -> String {
    generate_random_string(32)
}

/// Generates a random access token.
#[must_use]
pub fn generate_access_token() -> String {
    generate_random_string(32)
}

/// Generates a random refresh token.
#[must_use]
pub fn generate_refresh_token() -> String {
    generate_random_string(32)
}

/// Generates a cryptographically secure random string.
fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    base64_url_encode(&bytes)
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// OAuth token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// Token type (always "`DPoP`" for AT Protocol).
    pub token_type: String,
    /// Lifetime in seconds.
    pub expires_in: u64,
    /// The refresh token.
    pub refresh_token: String,
    /// Granted scope.
    pub scope: String,
    /// Subject (user DID).
    pub sub: String,
}

impl TokenResponse {
    /// Creates a new token response from token data.
    #[must_use]
    pub fn from_token_data(data: &TokenData) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            access_token: data.access_token.clone(),
            token_type: "DPoP".to_string(),
            expires_in: data.expires_at.saturating_sub(now),
            refresh_token: data.refresh_token.clone(),
            scope: data.scope.clone(),
            sub: data.sub.clone(),
        }
    }
}

/// Creates new token data for a user.
#[must_use]
pub fn create_tokens(
    client_id: impl Into<String>,
    sub: impl Into<String>,
    scope: impl Into<String>,
    dpop_jkt: Option<String>,
) -> TokenData {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    TokenData {
        access_token: generate_access_token(),
        refresh_token: generate_refresh_token(),
        client_id: client_id.into(),
        sub: sub.into(),
        scope: scope.into(),
        dpop_jkt,
        issued_at: now,
        expires_at: now + ACCESS_TOKEN_LIFETIME_SECS,
        revoked: false,
    }
}

/// Extracts the access token from an Authorization header.
///
/// # Errors
/// Returns an error if the header format is invalid.
pub fn extract_bearer_token(auth_header: &str) -> Result<&str> {
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("DPoP "))
        .ok_or_else(|| {
            crate::error::OAuthError::InvalidRequest("invalid Authorization header".into())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_auth_code() {
        let code1 = generate_auth_code();
        let code2 = generate_auth_code();

        assert!(!code1.is_empty());
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_create_tokens() {
        let tokens = create_tokens("client123", "did:plc:user", "atproto", None);

        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert!(!tokens.is_expired());
        assert!(tokens.is_valid());
    }

    #[test]
    fn test_token_response() {
        let tokens = create_tokens("client", "did:plc:user", "atproto", None);
        let response = TokenResponse::from_token_data(&tokens);

        assert_eq!(response.token_type, "DPoP");
        assert!(response.expires_in > 0);
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(extract_bearer_token("Bearer abc123").unwrap(), "abc123");
        assert_eq!(extract_bearer_token("DPoP xyz789").unwrap(), "xyz789");
        assert!(extract_bearer_token("Basic abc").is_err());
    }
}
