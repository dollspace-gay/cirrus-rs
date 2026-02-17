//! Authentication middleware and utilities.

use crate::error::{PdsError, Result};

/// Authentication context for a request.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated user's DID.
    pub did: String,
    /// The scope of the authentication.
    pub scope: String,
    /// Authentication method used.
    pub method: AuthMethod,
}

/// Session tokens returned on login.
#[derive(Debug, Clone)]
pub struct SessionTokens {
    /// Access JWT (short-lived).
    pub access_jwt: String,
    /// Refresh JWT (long-lived).
    pub refresh_jwt: String,
}

/// Authentication method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// DPoP-bound OAuth token.
    DpopOAuth,
    /// Session JWT (HS256).
    SessionJwt,
    /// Service JWT (ES256K).
    ServiceJwt,
    /// Static bearer token.
    StaticToken,
}

/// Verifies a static bearer token.
///
/// # Errors
/// Returns an error if the token is invalid.
pub fn verify_static_token(token: &str, expected: &str) -> Result<()> {
    if token == expected {
        Ok(())
    } else {
        Err(PdsError::AuthFailed("invalid token".into()))
    }
}

/// Verifies a session JWT.
///
/// # Errors
/// Returns an error if the JWT is invalid.
pub fn verify_session_jwt(token: &str, secret: &[u8], expected_did: &str) -> Result<AuthContext> {
    use cirrus_common::jwt::{verify_hs256, Claims};

    let claims: Claims =
        verify_hs256(token, secret).map_err(|e| PdsError::AuthFailed(e.to_string()))?;

    // Verify the subject matches expected DID
    let sub = claims.sub.as_deref().unwrap_or(&claims.iss);
    if sub != expected_did {
        return Err(PdsError::AuthFailed("subject mismatch".into()));
    }

    Ok(AuthContext {
        did: sub.to_string(),
        scope: claims.scope.unwrap_or_else(|| "atproto".to_string()),
        method: AuthMethod::SessionJwt,
    })
}

/// Creates a session access token.
///
/// # Errors
/// Returns an error if signing fails.
pub fn create_access_token(did: &str, secret: &[u8]) -> Result<String> {
    use cirrus_common::jwt::{sign_hs256, Claims};

    let claims = Claims::new(did, 7200) // 2 hours
        .with_sub(did)
        .with_scope("atproto");

    sign_hs256(&claims, secret).map_err(|e| PdsError::AuthFailed(e.to_string()))
}

/// Creates a session refresh token with a unique token ID.
///
/// Returns both the JWT string and the token ID (for DB persistence).
///
/// # Errors
/// Returns an error if signing fails.
pub fn create_refresh_token(did: &str, secret: &[u8]) -> Result<(String, String)> {
    use cirrus_common::jwt::{sign_hs256, Claims};

    let token_id = generate_token_id();
    let mut claims = Claims::new(did, 90 * 24 * 3600) // 90 days
        .with_sub(did)
        .with_scope("atproto:refresh");
    claims.jti = Some(token_id.clone());

    let jwt = sign_hs256(&claims, secret).map_err(|e| PdsError::AuthFailed(e.to_string()))?;
    Ok((jwt, token_id))
}

/// Generates a unique token ID for refresh tokens.
#[must_use]
pub fn generate_token_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..24).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}

/// Verifies a password against a bcrypt hash.
///
/// # Errors
/// Returns an error if the password is invalid.
pub fn verify_password(password: &str, hash: &str) -> Result<()> {
    bcrypt::verify(password, hash)
        .map_err(|e| PdsError::AuthFailed(format!("bcrypt error: {e}")))?
        .then_some(())
        .ok_or_else(|| PdsError::AuthFailed("invalid password".into()))
}

/// Hashes a password with bcrypt.
///
/// # Errors
/// Returns an error if hashing fails.
pub fn hash_password(password: &str) -> Result<String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| PdsError::AuthFailed(format!("bcrypt error: {e}")))
}

/// Configuration for session authentication on a single-user PDS.
pub struct SessionConfig<'a> {
    /// DID of the account owner.
    pub did: &'a str,
    /// Handle of the account owner.
    pub handle: &'a str,
    /// Bcrypt password hash.
    pub password_hash: &'a str,
    /// JWT signing secret.
    pub jwt_secret: &'a [u8],
}

/// Creates a new session (access + refresh tokens).
///
/// Verifies the identifier matches the configured DID or handle,
/// then verifies the password against the stored bcrypt hash.
///
/// # Errors
/// Returns an error if the identifier is unknown, password is wrong,
/// or token creation fails.
pub fn create_session(
    identifier: &str,
    password: &str,
    config: &SessionConfig<'_>,
) -> Result<(SessionTokens, String)> {
    if identifier != config.did && identifier != config.handle {
        return Err(PdsError::AuthFailed("identifier not found".into()));
    }

    verify_password(password, config.password_hash)?;

    let access_jwt = create_access_token(config.did, config.jwt_secret)?;
    let (refresh_jwt, token_id) = create_refresh_token(config.did, config.jwt_secret)?;

    Ok((
        SessionTokens {
            access_jwt,
            refresh_jwt,
        },
        token_id,
    ))
}

/// Refreshes session tokens.
///
/// Returns `SessionTokens` plus the new refresh token ID for DB persistence.
///
/// # Errors
/// Returns an error if token creation fails.
pub fn refresh_tokens(did: &str, secret: &[u8]) -> Result<(SessionTokens, String)> {
    let access_jwt = create_access_token(did, secret)?;
    let (refresh_jwt, new_token_id) = create_refresh_token(did, secret)?;

    Ok((
        SessionTokens {
            access_jwt,
            refresh_jwt,
        },
        new_token_id,
    ))
}

/// Generates a random app password in `xxxx-xxxx-xxxx-xxxx` format.
///
/// Uses lowercase alphanumeric characters (a-z, 2-7) encoded from
/// random bytes, split into 4 groups of 4 characters separated by hyphens.
#[must_use]
pub fn generate_app_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::thread_rng();
    let mut password = String::with_capacity(19); // 4*4 + 3 hyphens
    for group in 0..4u8 {
        if group > 0 {
            password.push('-');
        }
        for _ in 0..4u8 {
            let idx = rng.gen_range(0..CHARSET.len());
            password.push(char::from(CHARSET[idx]));
        }
    }
    password
}

/// Verifies authentication from an Authorization header.
///
/// # Errors
/// Returns an error if authentication fails.
pub fn verify_auth(
    auth_header: Option<&str>,
    secret: &[u8],
    expected_did: &str,
) -> Result<AuthContext> {
    let header = auth_header.ok_or_else(|| PdsError::AuthFailed("missing authorization".into()))?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| PdsError::AuthFailed("invalid authorization format".into()))?;

    verify_session_jwt(token, secret, expected_did)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_static_token() {
        assert!(verify_static_token("abc123", "abc123").is_ok());
        assert!(verify_static_token("wrong", "abc123").is_err());
    }

    #[test]
    fn test_session_jwt_roundtrip() {
        let secret = b"test-secret-key-for-jwt-signing";
        let did = "did:plc:testuser";

        let token = create_access_token(did, secret).unwrap();
        let context = verify_session_jwt(&token, secret, did).unwrap();

        assert_eq!(context.did, did);
        assert_eq!(context.method, AuthMethod::SessionJwt);
    }

    #[test]
    fn test_password_hashing() {
        let password = "secure-password-123";

        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).is_ok());
        assert!(verify_password("wrong-password", &hash).is_err());
    }

    #[test]
    fn test_create_session_valid_handle() {
        let secret = b"test-secret-key-for-jwt-signing";
        let password = "test-password";
        let hash = hash_password(password).unwrap();

        let config = SessionConfig {
            did: "did:plc:testuser",
            handle: "test.bsky.social",
            password_hash: &hash,
            jwt_secret: secret,
        };

        let result = create_session("test.bsky.social", password, &config);
        assert!(result.is_ok());
        let (tokens, token_id) = result.unwrap();
        assert!(!tokens.access_jwt.is_empty());
        assert!(!tokens.refresh_jwt.is_empty());
        assert!(!token_id.is_empty());
    }

    #[test]
    fn test_create_session_valid_did() {
        let secret = b"test-secret-key-for-jwt-signing";
        let password = "test-password";
        let hash = hash_password(password).unwrap();

        let config = SessionConfig {
            did: "did:plc:testuser",
            handle: "test.bsky.social",
            password_hash: &hash,
            jwt_secret: secret,
        };

        let result = create_session("did:plc:testuser", password, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_session_wrong_identifier() {
        let secret = b"test-secret-key-for-jwt-signing";
        let password = "test-password";
        let hash = hash_password(password).unwrap();

        let config = SessionConfig {
            did: "did:plc:testuser",
            handle: "test.bsky.social",
            password_hash: &hash,
            jwt_secret: secret,
        };

        let result = create_session("unknown.handle", password, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_session_wrong_password() {
        let secret = b"test-secret-key-for-jwt-signing";
        let hash = hash_password("correct-password").unwrap();

        let config = SessionConfig {
            did: "did:plc:testuser",
            handle: "test.bsky.social",
            password_hash: &hash,
            jwt_secret: secret,
        };

        let result = create_session("test.bsky.social", "wrong-password", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_app_password_format() {
        let password = generate_app_password();
        // Should be xxxx-xxxx-xxxx-xxxx format (19 chars total)
        assert_eq!(password.len(), 19);
        let parts: Vec<&str> = password.split('-').collect();
        assert_eq!(parts.len(), 4);
        for part in &parts {
            assert_eq!(part.len(), 4);
            assert!(part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_generate_app_password_uniqueness() {
        let p1 = generate_app_password();
        let p2 = generate_app_password();
        assert_ne!(p1, p2);
    }
}
