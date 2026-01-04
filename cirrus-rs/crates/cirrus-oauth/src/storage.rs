//! OAuth storage trait and data types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::par::ParRequest;
use crate::tokens::{AuthCodeData, TokenData};

/// Client metadata resolved from DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Client ID (typically a DID).
    pub client_id: String,
    /// Human-readable client name.
    pub client_name: Option<String>,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Client logo URL.
    pub logo_uri: Option<String>,
    /// Client homepage URL.
    pub client_uri: Option<String>,
    /// When the metadata was cached.
    pub cached_at: u64,
}

/// Storage trait for OAuth data.
///
/// Implementations must be thread-safe and handle concurrent access.
#[async_trait]
pub trait OAuthStorage: Send + Sync {
    // Authorization codes

    /// Saves an authorization code.
    async fn save_auth_code(&self, data: AuthCodeData) -> Result<()>;

    /// Retrieves and deletes an authorization code (one-time use).
    async fn consume_auth_code(&self, code: &str) -> Result<Option<AuthCodeData>>;

    // Tokens

    /// Saves token data.
    async fn save_token(&self, data: TokenData) -> Result<()>;

    /// Retrieves token data by access token.
    async fn get_token_by_access(&self, access_token: &str) -> Result<Option<TokenData>>;

    /// Retrieves token data by refresh token.
    async fn get_token_by_refresh(&self, refresh_token: &str) -> Result<Option<TokenData>>;

    /// Revokes a token (by access token).
    async fn revoke_token(&self, access_token: &str) -> Result<()>;

    /// Revokes all tokens for a subject.
    async fn revoke_all_tokens(&self, sub: &str) -> Result<()>;

    // Client metadata caching

    /// Caches client metadata.
    async fn cache_client(&self, metadata: ClientMetadata) -> Result<()>;

    /// Retrieves cached client metadata.
    async fn get_cached_client(&self, client_id: &str) -> Result<Option<ClientMetadata>>;

    // PAR requests

    /// Saves a PAR request.
    async fn save_par_request(&self, request_uri: &str, request: ParRequest) -> Result<()>;

    /// Retrieves and deletes a PAR request (one-time use).
    async fn consume_par_request(&self, request_uri: &str) -> Result<Option<ParRequest>>;

    // DPoP nonces

    /// Saves a DPoP nonce.
    async fn save_nonce(&self, nonce: &str) -> Result<()>;

    /// Checks if a nonce is valid (exists and not expired).
    async fn validate_nonce(&self, nonce: &str) -> Result<bool>;

    // Cleanup

    /// Removes expired entries (codes, tokens, nonces, etc.).
    async fn cleanup_expired(&self) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_metadata() {
        let metadata = ClientMetadata {
            client_id: "did:web:example.com".to_string(),
            client_name: Some("Example App".to_string()),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            logo_uri: None,
            client_uri: Some("https://example.com".to_string()),
            cached_at: 1234567890,
        };

        assert_eq!(metadata.client_id, "did:web:example.com");
        assert_eq!(metadata.redirect_uris.len(), 1);
    }
}
