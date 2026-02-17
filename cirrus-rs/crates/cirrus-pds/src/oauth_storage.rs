//! SQLite storage adapter for OAuth 2.1.
//!
//! Implements the [`OAuthStorage`] trait from cirrus-oauth using SQLite.

use async_trait::async_trait;
use parking_lot::Mutex;
use rusqlite::{params, Connection};

use cirrus_oauth::par::ParRequest;
use cirrus_oauth::storage::{ClientMetadata, OAuthStorage};
use cirrus_oauth::tokens::{AuthCodeData, TokenData};

use crate::error::Result;

/// Nonce lifetime in seconds (5 minutes).
const NONCE_LIFETIME_SECS: u64 = 300;

/// SQLite storage for OAuth data.
pub struct OAuthSqliteStorage {
    conn: Mutex<Connection>,
}

#[allow(clippy::significant_drop_tightening)]
impl OAuthSqliteStorage {
    /// Creates a new in-memory OAuth storage.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates a new OAuth storage with a file path.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.lock().execute_batch(
            r"
            -- Authorization codes (short-lived, one-time use)
            CREATE TABLE IF NOT EXISTS oauth_auth_codes (
                code TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                scope TEXT NOT NULL,
                sub TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            -- Access/refresh tokens
            CREATE TABLE IF NOT EXISTS oauth_tokens (
                access_token TEXT PRIMARY KEY,
                refresh_token TEXT NOT NULL UNIQUE,
                client_id TEXT NOT NULL,
                sub TEXT NOT NULL,
                scope TEXT NOT NULL,
                dpop_jkt TEXT,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked INTEGER DEFAULT 0
            );

            -- Client metadata cache
            CREATE TABLE IF NOT EXISTS oauth_client_cache (
                client_id TEXT PRIMARY KEY,
                client_name TEXT,
                redirect_uris TEXT NOT NULL,
                logo_uri TEXT,
                client_uri TEXT,
                cached_at INTEGER NOT NULL
            );

            -- PAR (Pushed Authorization Requests)
            CREATE TABLE IF NOT EXISTS oauth_par_requests (
                request_uri TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                state TEXT,
                nonce TEXT,
                expires_at INTEGER NOT NULL
            );

            -- DPoP nonces
            CREATE TABLE IF NOT EXISTS oauth_nonces (
                nonce TEXT PRIMARY KEY,
                expires_at INTEGER NOT NULL
            );

            -- Indexes for common lookups
            CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh ON oauth_tokens(refresh_token);
            CREATE INDEX IF NOT EXISTS idx_oauth_tokens_sub ON oauth_tokens(sub);
            CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires ON oauth_auth_codes(expires_at);
            CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at);
            CREATE INDEX IF NOT EXISTS idx_oauth_par_expires ON oauth_par_requests(expires_at);
            CREATE INDEX IF NOT EXISTS idx_oauth_nonces_expires ON oauth_nonces(expires_at);
            ",
        )?;

        Ok(())
    }

    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Non-consuming PAR request lookup.
    ///
    /// Used by the authorization consent page to display request details
    /// without deleting the request (which is consumed later on approval).
    pub fn get_par_request(&self, request_uri: &str) -> Option<ParRequest> {
        self.conn.lock().query_row(
            "SELECT client_id, redirect_uri, scope, code_challenge, code_challenge_method, state, nonce, expires_at
             FROM oauth_par_requests WHERE request_uri = ?",
            params![request_uri],
            |row| {
                Ok(ParRequest {
                    client_id: row.get(0)?,
                    redirect_uri: row.get(1)?,
                    scope: row.get(2)?,
                    code_challenge: row.get(3)?,
                    code_challenge_method: row.get(4)?,
                    state: row.get(5)?,
                    nonce: row.get(6)?,
                    expires_at: row.get::<_, i64>(7)? as u64,
                })
            },
        ).ok()
    }

    /// Synchronous token lookup by access token.
    ///
    /// This is used by the auth middleware which runs in a synchronous
    /// context. The underlying storage uses `parking_lot::Mutex` so
    /// this is safe to call from async code.
    pub fn get_token_sync(&self, access_token: &str) -> Option<TokenData> {
        self.conn.lock().query_row(
            "SELECT access_token, refresh_token, client_id, sub, scope, dpop_jkt, issued_at, expires_at, revoked
             FROM oauth_tokens WHERE access_token = ?",
            params![access_token],
            |row| {
                Ok(TokenData {
                    access_token: row.get(0)?,
                    refresh_token: row.get(1)?,
                    client_id: row.get(2)?,
                    sub: row.get(3)?,
                    scope: row.get(4)?,
                    dpop_jkt: row.get(5)?,
                    issued_at: row.get::<_, i64>(6)? as u64,
                    expires_at: row.get::<_, i64>(7)? as u64,
                    revoked: row.get::<_, i32>(8)? != 0,
                })
            },
        ).ok()
    }
}

#[async_trait]
impl OAuthStorage for OAuthSqliteStorage {
    // Authorization codes

    async fn save_auth_code(&self, data: AuthCodeData) -> cirrus_oauth::Result<()> {
        self.conn.lock().execute(
            "INSERT INTO oauth_auth_codes (code, client_id, redirect_uri, code_challenge, scope, sub, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                data.code,
                data.client_id,
                data.redirect_uri,
                data.code_challenge,
                data.scope,
                data.sub,
                data.expires_at as i64
            ],
        ).map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn consume_auth_code(&self, code: &str) -> cirrus_oauth::Result<Option<AuthCodeData>> {
        let conn = self.conn.lock();

        // Get and delete in one transaction
        let result = conn.query_row(
            "SELECT client_id, redirect_uri, code_challenge, scope, sub, expires_at
             FROM oauth_auth_codes WHERE code = ?",
            params![code],
            |row| {
                Ok(AuthCodeData {
                    code: code.to_string(),
                    client_id: row.get(0)?,
                    redirect_uri: row.get(1)?,
                    code_challenge: row.get(2)?,
                    scope: row.get(3)?,
                    sub: row.get(4)?,
                    expires_at: row.get::<_, i64>(5)? as u64,
                })
            },
        );

        match result {
            Ok(data) => {
                // Delete the code (one-time use)
                conn.execute("DELETE FROM oauth_auth_codes WHERE code = ?", params![code])
                    .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    // Tokens

    async fn save_token(&self, data: TokenData) -> cirrus_oauth::Result<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO oauth_tokens
             (access_token, refresh_token, client_id, sub, scope, dpop_jkt, issued_at, expires_at, revoked)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                data.access_token,
                data.refresh_token,
                data.client_id,
                data.sub,
                data.scope,
                data.dpop_jkt,
                data.issued_at as i64,
                data.expires_at as i64,
                i32::from(data.revoked)
            ],
        ).map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn get_token_by_access(
        &self,
        access_token: &str,
    ) -> cirrus_oauth::Result<Option<TokenData>> {
        let result = self.conn.lock().query_row(
            "SELECT access_token, refresh_token, client_id, sub, scope, dpop_jkt, issued_at, expires_at, revoked
             FROM oauth_tokens WHERE access_token = ?",
            params![access_token],
            |row| {
                Ok(TokenData {
                    access_token: row.get(0)?,
                    refresh_token: row.get(1)?,
                    client_id: row.get(2)?,
                    sub: row.get(3)?,
                    scope: row.get(4)?,
                    dpop_jkt: row.get(5)?,
                    issued_at: row.get::<_, i64>(6)? as u64,
                    expires_at: row.get::<_, i64>(7)? as u64,
                    revoked: row.get::<_, i32>(8)? != 0,
                })
            },
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    async fn get_token_by_refresh(
        &self,
        refresh_token: &str,
    ) -> cirrus_oauth::Result<Option<TokenData>> {
        let result = self.conn.lock().query_row(
            "SELECT access_token, refresh_token, client_id, sub, scope, dpop_jkt, issued_at, expires_at, revoked
             FROM oauth_tokens WHERE refresh_token = ?",
            params![refresh_token],
            |row| {
                Ok(TokenData {
                    access_token: row.get(0)?,
                    refresh_token: row.get(1)?,
                    client_id: row.get(2)?,
                    sub: row.get(3)?,
                    scope: row.get(4)?,
                    dpop_jkt: row.get(5)?,
                    issued_at: row.get::<_, i64>(6)? as u64,
                    expires_at: row.get::<_, i64>(7)? as u64,
                    revoked: row.get::<_, i32>(8)? != 0,
                })
            },
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    async fn revoke_token(&self, access_token: &str) -> cirrus_oauth::Result<()> {
        self.conn
            .lock()
            .execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE access_token = ?",
                params![access_token],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn revoke_all_tokens(&self, sub: &str) -> cirrus_oauth::Result<()> {
        self.conn
            .lock()
            .execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE sub = ?",
                params![sub],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    // Client metadata caching

    async fn cache_client(&self, metadata: ClientMetadata) -> cirrus_oauth::Result<()> {
        let redirect_uris_json = serde_json::to_string(&metadata.redirect_uris)
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;

        self.conn
            .lock()
            .execute(
                "INSERT OR REPLACE INTO oauth_client_cache
             (client_id, client_name, redirect_uris, logo_uri, client_uri, cached_at)
             VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    metadata.client_id,
                    metadata.client_name,
                    redirect_uris_json,
                    metadata.logo_uri,
                    metadata.client_uri,
                    metadata.cached_at as i64
                ],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn get_cached_client(
        &self,
        client_id: &str,
    ) -> cirrus_oauth::Result<Option<ClientMetadata>> {
        let result = self.conn.lock().query_row(
            "SELECT client_id, client_name, redirect_uris, logo_uri, client_uri, cached_at
             FROM oauth_client_cache WHERE client_id = ?",
            params![client_id],
            |row| {
                let redirect_uris_json: String = row.get(2)?;
                let redirect_uris: Vec<String> =
                    serde_json::from_str(&redirect_uris_json).unwrap_or_default();

                Ok(ClientMetadata {
                    client_id: row.get(0)?,
                    client_name: row.get(1)?,
                    redirect_uris,
                    logo_uri: row.get(3)?,
                    client_uri: row.get(4)?,
                    cached_at: row.get::<_, i64>(5)? as u64,
                })
            },
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    // PAR requests

    async fn save_par_request(
        &self,
        request_uri: &str,
        request: ParRequest,
    ) -> cirrus_oauth::Result<()> {
        self.conn.lock().execute(
            "INSERT INTO oauth_par_requests
             (request_uri, client_id, redirect_uri, scope, code_challenge, code_challenge_method, state, nonce, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                request_uri,
                request.client_id,
                request.redirect_uri,
                request.scope,
                request.code_challenge,
                request.code_challenge_method,
                request.state,
                request.nonce,
                request.expires_at as i64
            ],
        ).map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn consume_par_request(
        &self,
        request_uri: &str,
    ) -> cirrus_oauth::Result<Option<ParRequest>> {
        let conn = self.conn.lock();

        let result = conn.query_row(
            "SELECT client_id, redirect_uri, scope, code_challenge, code_challenge_method, state, nonce, expires_at
             FROM oauth_par_requests WHERE request_uri = ?",
            params![request_uri],
            |row| {
                Ok(ParRequest {
                    client_id: row.get(0)?,
                    redirect_uri: row.get(1)?,
                    scope: row.get(2)?,
                    code_challenge: row.get(3)?,
                    code_challenge_method: row.get(4)?,
                    state: row.get(5)?,
                    nonce: row.get(6)?,
                    expires_at: row.get::<_, i64>(7)? as u64,
                })
            },
        );

        match result {
            Ok(data) => {
                // Delete the request (one-time use)
                conn.execute(
                    "DELETE FROM oauth_par_requests WHERE request_uri = ?",
                    params![request_uri],
                )
                .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
                Ok(Some(data))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    // DPoP nonces

    async fn save_nonce(&self, nonce: &str) -> cirrus_oauth::Result<()> {
        let expires_at = Self::current_timestamp() + NONCE_LIFETIME_SECS;
        self.conn
            .lock()
            .execute(
                "INSERT OR REPLACE INTO oauth_nonces (nonce, expires_at) VALUES (?, ?)",
                params![nonce, expires_at as i64],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        Ok(())
    }

    async fn validate_nonce(&self, nonce: &str) -> cirrus_oauth::Result<bool> {
        let now = Self::current_timestamp();
        let result = self.conn.lock().query_row(
            "SELECT 1 FROM oauth_nonces WHERE nonce = ? AND expires_at > ?",
            params![nonce, now as i64],
            |_| Ok(()),
        );

        match result {
            Ok(()) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(cirrus_oauth::OAuthError::ServerError(e.to_string())),
        }
    }

    // Cleanup

    async fn cleanup_expired(&self) -> cirrus_oauth::Result<u64> {
        let now = Self::current_timestamp() as i64;
        let conn = self.conn.lock();

        let mut total = 0u64;

        // Clean up expired auth codes
        let deleted = conn
            .execute(
                "DELETE FROM oauth_auth_codes WHERE expires_at < ?",
                params![now],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        total += deleted as u64;

        // Clean up expired tokens (keep revoked ones for audit, but clean very old ones)
        let deleted = conn
            .execute(
                "DELETE FROM oauth_tokens WHERE expires_at < ? AND revoked = 1",
                params![now - 86400], // Keep revoked tokens for 1 day
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        total += deleted as u64;

        // Clean up expired PAR requests
        let deleted = conn
            .execute(
                "DELETE FROM oauth_par_requests WHERE expires_at < ?",
                params![now],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        total += deleted as u64;

        // Clean up expired nonces
        let deleted = conn
            .execute(
                "DELETE FROM oauth_nonces WHERE expires_at < ?",
                params![now],
            )
            .map_err(|e| cirrus_oauth::OAuthError::ServerError(e.to_string()))?;
        total += deleted as u64;

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_code_lifecycle() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let code_data = AuthCodeData {
            code: "test_code_123".to_string(),
            client_id: "client_abc".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            code_challenge: "challenge_xyz".to_string(),
            scope: "atproto".to_string(),
            sub: "did:plc:user123".to_string(),
            expires_at: OAuthSqliteStorage::current_timestamp() + 300,
        };

        // Save code
        storage.save_auth_code(code_data.clone()).await.unwrap();

        // Consume code (first time succeeds)
        let retrieved = storage.consume_auth_code("test_code_123").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client_id, "client_abc");
        assert_eq!(retrieved.sub, "did:plc:user123");

        // Consume again (should be None - one-time use)
        let retrieved = storage.consume_auth_code("test_code_123").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_token_lifecycle() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let token_data = TokenData {
            access_token: "access_123".to_string(),
            refresh_token: "refresh_456".to_string(),
            client_id: "client_abc".to_string(),
            sub: "did:plc:user123".to_string(),
            scope: "atproto".to_string(),
            dpop_jkt: Some("thumbprint_xyz".to_string()),
            issued_at: OAuthSqliteStorage::current_timestamp(),
            expires_at: OAuthSqliteStorage::current_timestamp() + 3600,
            revoked: false,
        };

        // Save token
        storage.save_token(token_data.clone()).await.unwrap();

        // Get by access token
        let retrieved = storage.get_token_by_access("access_123").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client_id, "client_abc");
        assert!(!retrieved.revoked);

        // Get by refresh token
        let retrieved = storage.get_token_by_refresh("refresh_456").await.unwrap();
        assert!(retrieved.is_some());

        // Revoke token
        storage.revoke_token("access_123").await.unwrap();
        let retrieved = storage.get_token_by_access("access_123").await.unwrap();
        assert!(retrieved.unwrap().revoked);

        // Non-existent token
        let retrieved = storage.get_token_by_access("nonexistent").await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_revoke_all_tokens() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        // Save multiple tokens for same user
        for i in 0..3 {
            let token_data = TokenData {
                access_token: format!("access_{i}"),
                refresh_token: format!("refresh_{i}"),
                client_id: "client_abc".to_string(),
                sub: "did:plc:user123".to_string(),
                scope: "atproto".to_string(),
                dpop_jkt: None,
                issued_at: OAuthSqliteStorage::current_timestamp(),
                expires_at: OAuthSqliteStorage::current_timestamp() + 3600,
                revoked: false,
            };
            storage.save_token(token_data).await.unwrap();
        }

        // Revoke all for user
        storage.revoke_all_tokens("did:plc:user123").await.unwrap();

        // All should be revoked
        for i in 0..3 {
            let token = storage
                .get_token_by_access(&format!("access_{i}"))
                .await
                .unwrap();
            assert!(token.unwrap().revoked);
        }
    }

    #[tokio::test]
    async fn test_client_cache() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let metadata = ClientMetadata {
            client_id: "did:web:example.com".to_string(),
            client_name: Some("Example App".to_string()),
            redirect_uris: vec![
                "https://example.com/callback".to_string(),
                "https://example.com/callback2".to_string(),
            ],
            logo_uri: Some("https://example.com/logo.png".to_string()),
            client_uri: Some("https://example.com".to_string()),
            cached_at: OAuthSqliteStorage::current_timestamp(),
        };

        // Cache client
        storage.cache_client(metadata.clone()).await.unwrap();

        // Get cached client
        let retrieved = storage
            .get_cached_client("did:web:example.com")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client_name, Some("Example App".to_string()));
        assert_eq!(retrieved.redirect_uris.len(), 2);

        // Non-existent client
        let retrieved = storage
            .get_cached_client("did:web:unknown.com")
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_par_request_lifecycle() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let request = ParRequest {
            client_id: "client_abc".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "atproto".to_string(),
            code_challenge: "challenge_xyz".to_string(),
            code_challenge_method: "S256".to_string(),
            state: Some("state_123".to_string()),
            nonce: None,
            expires_at: OAuthSqliteStorage::current_timestamp() + 90,
        };

        let request_uri = "urn:ietf:params:oauth:request_uri:abc123";

        // Save PAR request
        storage
            .save_par_request(request_uri, request.clone())
            .await
            .unwrap();

        // Consume PAR request (first time succeeds)
        let retrieved = storage.consume_par_request(request_uri).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client_id, "client_abc");
        assert_eq!(retrieved.state, Some("state_123".to_string()));

        // Consume again (should be None - one-time use)
        let retrieved = storage.consume_par_request(request_uri).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        // Save nonce
        storage.save_nonce("nonce_123").await.unwrap();

        // Validate (should be valid)
        assert!(storage.validate_nonce("nonce_123").await.unwrap());

        // Unknown nonce
        assert!(!storage.validate_nonce("unknown_nonce").await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        // Add expired auth code
        let expired_code = AuthCodeData {
            code: "expired_code".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com".to_string(),
            code_challenge: "challenge".to_string(),
            scope: "atproto".to_string(),
            sub: "did:plc:user".to_string(),
            expires_at: 1, // Expired long ago
        };
        storage.save_auth_code(expired_code).await.unwrap();

        // Add valid auth code
        let valid_code = AuthCodeData {
            code: "valid_code".to_string(),
            client_id: "client".to_string(),
            redirect_uri: "https://example.com".to_string(),
            code_challenge: "challenge".to_string(),
            scope: "atproto".to_string(),
            sub: "did:plc:user".to_string(),
            expires_at: OAuthSqliteStorage::current_timestamp() + 300,
        };
        storage.save_auth_code(valid_code).await.unwrap();

        // Run cleanup
        let cleaned = storage.cleanup_expired().await.unwrap();
        assert!(cleaned >= 1);

        // Expired code should be gone
        let code = storage.consume_auth_code("expired_code").await.unwrap();
        assert!(code.is_none());

        // Valid code should still exist
        let code = storage.consume_auth_code("valid_code").await.unwrap();
        assert!(code.is_some());
    }

    #[tokio::test]
    async fn test_get_token_sync() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let token_data = TokenData {
            access_token: "sync_access_123".to_string(),
            refresh_token: "sync_refresh_456".to_string(),
            client_id: "client_abc".to_string(),
            sub: "did:plc:user123".to_string(),
            scope: "atproto".to_string(),
            dpop_jkt: Some("thumbprint_xyz".to_string()),
            issued_at: OAuthSqliteStorage::current_timestamp(),
            expires_at: OAuthSqliteStorage::current_timestamp() + 3600,
            revoked: false,
        };

        // Save via async method
        storage.save_token(token_data).await.unwrap();

        // Retrieve via sync method
        let retrieved = storage.get_token_sync("sync_access_123");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.sub, "did:plc:user123");
        assert_eq!(retrieved.dpop_jkt, Some("thumbprint_xyz".to_string()));

        // Non-existent token
        let missing = storage.get_token_sync("nonexistent");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_get_par_request_non_consuming() {
        let storage = OAuthSqliteStorage::in_memory().unwrap();

        let request = ParRequest {
            client_id: "client_abc".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: "atproto".to_string(),
            code_challenge: "challenge_xyz".to_string(),
            code_challenge_method: "S256".to_string(),
            state: Some("state_123".to_string()),
            nonce: None,
            expires_at: OAuthSqliteStorage::current_timestamp() + 90,
        };

        let request_uri = "urn:ietf:params:oauth:request_uri:peek_test";
        storage
            .save_par_request(request_uri, request)
            .await
            .unwrap();

        // Non-consuming read should return data
        let retrieved = storage.get_par_request(request_uri);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().client_id, "client_abc");

        // Read again — should still be there (non-consuming)
        let still_there = storage.get_par_request(request_uri);
        assert!(still_there.is_some());

        // Consuming read should still work after non-consuming reads
        let consumed = storage.consume_par_request(request_uri).await.unwrap();
        assert!(consumed.is_some());

        // Now it should be gone
        let gone = storage.get_par_request(request_uri);
        assert!(gone.is_none());
    }
}
