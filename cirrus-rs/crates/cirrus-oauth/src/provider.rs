//! OAuth 2.1 provider implementation.

use crate::error::{OAuthError, Result};
use crate::pkce;
use crate::storage::OAuthStorage;
use crate::tokens::{self, AuthCodeData, TokenData, TokenResponse, AUTH_CODE_LIFETIME_SECS};

/// OAuth provider configuration.
#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    /// The issuer identifier (PDS URL).
    pub issuer: String,
    /// The user's DID.
    pub subject: String,
}

/// OAuth 2.1 provider for AT Protocol.
pub struct OAuthProvider<S: OAuthStorage> {
    config: OAuthProviderConfig,
    storage: S,
}

impl<S: OAuthStorage> OAuthProvider<S> {
    /// Creates a new OAuth provider.
    #[must_use]
    pub fn new(config: OAuthProviderConfig, storage: S) -> Self {
        Self { config, storage }
    }

    /// Handles an authorization request and generates an auth code.
    ///
    /// # Errors
    /// Returns an error if the request is invalid.
    pub async fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        code_challenge: &str,
    ) -> Result<String> {
        // In a real implementation, we'd validate the client and redirect URI here
        // For now, we just generate the code

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let code = tokens::generate_auth_code();

        let auth_code_data = AuthCodeData {
            code: code.clone(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: code_challenge.to_string(),
            scope: scope.to_string(),
            sub: self.config.subject.clone(),
            expires_at: now + AUTH_CODE_LIFETIME_SECS,
        };

        self.storage.save_auth_code(auth_code_data).await?;

        Ok(code)
    }

    /// Exchanges an authorization code for tokens.
    ///
    /// # Errors
    /// Returns an error if the code is invalid or PKCE verification fails.
    pub async fn token(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse> {
        // Consume the authorization code
        let auth_code = self
            .storage
            .consume_auth_code(code)
            .await?
            .ok_or_else(|| OAuthError::InvalidGrant("invalid or expired code".into()))?;

        // Verify client_id matches
        if auth_code.client_id != client_id {
            return Err(OAuthError::InvalidGrant("client_id mismatch".into()));
        }

        // Verify redirect_uri matches
        if auth_code.redirect_uri != redirect_uri {
            return Err(OAuthError::InvalidGrant("redirect_uri mismatch".into()));
        }

        // Verify PKCE
        pkce::verify_challenge(code_verifier, &auth_code.code_challenge)?;

        // Generate tokens
        let token_data = tokens::create_tokens(
            client_id,
            &auth_code.sub,
            &auth_code.scope,
            dpop_jkt,
        );

        self.storage.save_token(token_data.clone()).await?;

        Ok(TokenResponse::from_token_data(&token_data))
    }

    /// Refreshes an access token using a refresh token.
    ///
    /// # Errors
    /// Returns an error if the refresh token is invalid.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse> {
        // Find token by refresh token
        let old_token = self
            .storage
            .get_token_by_refresh(refresh_token)
            .await?
            .ok_or_else(|| OAuthError::InvalidGrant("invalid refresh token".into()))?;

        if old_token.revoked {
            return Err(OAuthError::TokenRevoked);
        }

        // Verify DPoP binding if applicable
        if let Some(ref old_jkt) = old_token.dpop_jkt {
            match &dpop_jkt {
                Some(new_jkt) if new_jkt != old_jkt => {
                    return Err(OAuthError::DpopError("DPoP key mismatch".into()));
                }
                None => {
                    return Err(OAuthError::DpopError("missing DPoP proof".into()));
                }
                _ => {}
            }
        }

        // Revoke old token
        self.storage.revoke_token(&old_token.access_token).await?;

        // Generate new tokens
        let new_token = tokens::create_tokens(
            &old_token.client_id,
            &old_token.sub,
            &old_token.scope,
            dpop_jkt,
        );

        self.storage.save_token(new_token.clone()).await?;

        Ok(TokenResponse::from_token_data(&new_token))
    }

    /// Verifies an access token.
    ///
    /// # Errors
    /// Returns an error if the token is invalid.
    pub async fn verify_token(
        &self,
        access_token: &str,
        dpop_jkt: Option<&str>,
    ) -> Result<TokenData> {
        let token = self
            .storage
            .get_token_by_access(access_token)
            .await?
            .ok_or_else(|| OAuthError::InvalidGrant("invalid access token".into()))?;

        if token.revoked {
            return Err(OAuthError::TokenRevoked);
        }

        if token.is_expired() {
            return Err(OAuthError::TokenExpired);
        }

        // Verify DPoP binding
        if let Some(ref expected_jkt) = token.dpop_jkt {
            match dpop_jkt {
                Some(jkt) if jkt != expected_jkt => {
                    return Err(OAuthError::DpopError("DPoP key mismatch".into()));
                }
                None => {
                    return Err(OAuthError::DpopError("missing DPoP proof".into()));
                }
                _ => {}
            }
        }

        Ok(token)
    }

    /// Revokes a token.
    ///
    /// # Errors
    /// Returns an error if revocation fails.
    pub async fn revoke(&self, token: &str) -> Result<()> {
        // Try to revoke by access token first
        if self.storage.get_token_by_access(token).await?.is_some() {
            self.storage.revoke_token(token).await?;
            return Ok(());
        }

        // Try by refresh token
        if let Some(token_data) = self.storage.get_token_by_refresh(token).await? {
            self.storage.revoke_token(&token_data.access_token).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_config() {
        let config = OAuthProviderConfig {
            issuer: "https://pds.example.com".to_string(),
            subject: "did:plc:user123".to_string(),
        };

        assert_eq!(config.issuer, "https://pds.example.com");
        assert_eq!(config.subject, "did:plc:user123");
    }
}
