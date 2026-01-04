//! JWT utilities for AT Protocol authentication.
//!
//! Supports HS256 for session tokens and ES256K for service auth.

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::crypto::Keypair;
use crate::error::Error;

/// Standard JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer (typically a DID).
    pub iss: String,
    /// Subject (typically a DID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience (typically a DID or service URL).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued at time (Unix timestamp).
    pub iat: u64,
    /// JWT ID (unique identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Scope (space-separated list of permissions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Lexicon method (for service auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lxm: Option<String>,
}

impl Claims {
    /// Creates new claims with the given issuer and expiration.
    #[must_use]
    pub fn new(iss: impl Into<String>, exp_seconds: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            iss: iss.into(),
            sub: None,
            aud: None,
            exp: now + exp_seconds,
            iat: now,
            jti: None,
            scope: None,
            lxm: None,
        }
    }

    /// Sets the subject claim.
    #[must_use]
    pub fn with_sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// Sets the audience claim.
    #[must_use]
    pub fn with_aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// Sets the JWT ID claim.
    #[must_use]
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Sets the scope claim.
    #[must_use]
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Sets the lexicon method claim.
    #[must_use]
    pub fn with_lxm(mut self, lxm: impl Into<String>) -> Self {
        self.lxm = Some(lxm.into());
        self
    }

    /// Checks if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.exp < now
    }
}

// ============================================================================
// HS256 (HMAC-SHA256) - for session tokens
// ============================================================================

/// Signs a JWT with HS256 (HMAC-SHA256).
///
/// # Errors
/// Returns an error if signing fails.
pub fn sign_hs256<T: Serialize>(claims: &T, secret: &[u8]) -> Result<String, Error> {
    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret);

    jsonwebtoken::encode(&header, claims, &encoding_key)
        .map_err(|e| Error::Jwt(format!("signing failed: {e}")))
}

/// Verifies a JWT with HS256 (HMAC-SHA256).
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_hs256<T: DeserializeOwned>(token: &str, secret: &[u8]) -> Result<T, Error> {
    let decoding_key = DecodingKey::from_secret(secret);

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .map_err(|e| Error::Jwt(format!("verification failed: {e}")))?;

    Ok(token_data.claims)
}

// ============================================================================
// ES256K (ECDSA with secp256k1) - for service auth
// ============================================================================

/// ES256K JWT header.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Es256kHeader {
    alg: String,
    typ: String,
}

impl Default for Es256kHeader {
    fn default() -> Self {
        Self {
            alg: "ES256K".to_string(),
            typ: "JWT".to_string(),
        }
    }
}

/// Signs a JWT with ES256K (ECDSA with secp256k1).
///
/// # Errors
/// Returns an error if signing fails.
pub fn sign_es256k<T: Serialize>(claims: &T, keypair: &Keypair) -> Result<String, Error> {
    let header = Es256kHeader::default();

    // Encode header
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| Error::Jwt(format!("header serialization failed: {e}")))?;
    let header_b64 = base64_url_encode(&header_json);

    // Encode payload
    let payload_json = serde_json::to_vec(claims)
        .map_err(|e| Error::Jwt(format!("payload serialization failed: {e}")))?;
    let payload_b64 = base64_url_encode(&payload_json);

    // Create signing input
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with secp256k1
    let signature = keypair
        .sign(signing_input.as_bytes())
        .map_err(|e| Error::Jwt(format!("signing failed: {e}")))?;

    // Encode signature
    let signature_b64 = base64_url_encode(&signature);

    Ok(format!("{signing_input}.{signature_b64}"))
}

/// Verifies a JWT with ES256K (ECDSA with secp256k1).
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_es256k<T: DeserializeOwned>(
    token: &str,
    verifying_key: &VerifyingKey,
) -> Result<T, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("invalid token format".into()));
    }

    // Decode and verify header
    let header_bytes = base64_url_decode(parts[0])?;
    let header: Es256kHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::Jwt(format!("invalid header JSON: {e}")))?;

    if header.alg != "ES256K" {
        return Err(Error::Jwt(format!(
            "unexpected algorithm: {}, expected ES256K",
            header.alg
        )));
    }

    // Verify signature
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = base64_url_decode(parts[2])?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| Error::Jwt(format!("invalid signature format: {e}")))?;

    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| Error::Jwt(format!("signature verification failed: {e}")))?;

    // Decode payload
    let payload_bytes = base64_url_decode(parts[1])?;
    let claims: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Jwt(format!("invalid payload JSON: {e}")))?;

    Ok(claims)
}

/// Verifies a JWT with ES256K using a public key from bytes.
///
/// # Errors
/// Returns an error if verification fails or the key is invalid.
pub fn verify_es256k_with_key<T: DeserializeOwned>(
    token: &str,
    public_key_bytes: &[u8],
) -> Result<T, Error> {
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| Error::Jwt(format!("invalid public key: {e}")))?;

    verify_es256k(token, &verifying_key)
}

// ============================================================================
// Utility functions
// ============================================================================

/// Decodes a JWT without verification (for inspection only).
///
/// # Errors
/// Returns an error if the token format is invalid.
pub fn decode_unverified<T: DeserializeOwned>(token: &str) -> Result<T, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("invalid token format".into()));
    }

    let payload = base64_url_decode(parts[1])?;
    serde_json::from_slice(&payload).map_err(|e| Error::Jwt(format!("invalid JSON: {e}")))
}

/// Extracts the header from a JWT without verification.
///
/// # Errors
/// Returns an error if the token format is invalid.
pub fn decode_header(token: &str) -> Result<Header, Error> {
    jsonwebtoken::decode_header(token).map_err(|e| Error::Jwt(format!("invalid header: {e}")))
}

/// Header for extracting algorithm.
#[derive(Deserialize)]
struct AlgHeader {
    alg: String,
}

/// Extracts the algorithm from a JWT header.
///
/// # Errors
/// Returns an error if the token format is invalid.
pub fn get_algorithm(token: &str) -> Result<String, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("invalid token format".into()));
    }

    let header_bytes = base64_url_decode(parts[0])?;
    let header: AlgHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::Jwt(format!("invalid header JSON: {e}")))?;

    Ok(header.alg)
}

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| Error::Jwt(format!("invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    #[test]
    fn test_claims_creation() {
        let claims = Claims::new("did:plc:test", 3600)
            .with_sub("did:plc:user")
            .with_aud("did:web:service.com")
            .with_scope("atproto");

        assert_eq!(claims.iss, "did:plc:test");
        assert_eq!(claims.sub, Some("did:plc:user".to_string()));
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_hs256_roundtrip() {
        let secret = b"super-secret-key-for-testing-123";
        let claims = Claims::new("test-issuer", 3600);

        let token = sign_hs256(&claims, secret).unwrap();
        let decoded: Claims = verify_hs256(&token, secret).unwrap();

        assert_eq!(claims.iss, decoded.iss);
    }

    #[test]
    fn test_hs256_wrong_secret() {
        let secret = b"correct-secret";
        let wrong_secret = b"wrong-secret-xx";
        let claims = Claims::new("test-issuer", 3600);

        let token = sign_hs256(&claims, secret).unwrap();
        let result: Result<Claims, _> = verify_hs256(&token, wrong_secret);

        assert!(result.is_err());
    }

    #[test]
    fn test_es256k_roundtrip() {
        let keypair = Keypair::generate();
        let claims = Claims::new("did:plc:issuer", 3600)
            .with_sub("did:plc:subject")
            .with_aud("did:web:service.example.com")
            .with_lxm("com.atproto.repo.createRecord");

        let token = sign_es256k(&claims, &keypair).unwrap();

        // Get the verifying key from the keypair
        let public_key = keypair.public_key();
        let public_key_bytes = public_key.to_bytes();
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes).unwrap();

        let decoded: Claims = verify_es256k(&token, &verifying_key).unwrap();

        assert_eq!(claims.iss, decoded.iss);
        assert_eq!(claims.sub, decoded.sub);
        assert_eq!(claims.aud, decoded.aud);
        assert_eq!(claims.lxm, decoded.lxm);
    }

    #[test]
    fn test_es256k_wrong_key() {
        let keypair = Keypair::generate();
        let wrong_keypair = Keypair::generate();
        let claims = Claims::new("test-issuer", 3600);

        let token = sign_es256k(&claims, &keypair).unwrap();

        let wrong_public_key = wrong_keypair.public_key();
        let wrong_key_bytes = wrong_public_key.to_bytes();
        let wrong_verifying_key = VerifyingKey::from_sec1_bytes(&wrong_key_bytes).unwrap();

        let result: Result<Claims, _> = verify_es256k(&token, &wrong_verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_algorithm() {
        let keypair = Keypair::generate();
        let claims = Claims::new("test", 3600);

        let es256k_token = sign_es256k(&claims, &keypair).unwrap();
        assert_eq!(get_algorithm(&es256k_token).unwrap(), "ES256K");

        let hs256_token = sign_hs256(&claims, b"secret").unwrap();
        assert_eq!(get_algorithm(&hs256_token).unwrap(), "HS256");
    }

    #[test]
    fn test_decode_unverified() {
        let secret = b"secret";
        let claims = Claims::new("test-issuer", 3600).with_sub("test-subject");

        let token = sign_hs256(&claims, secret).unwrap();
        let decoded: Claims = decode_unverified(&token).unwrap();

        assert_eq!(decoded.iss, "test-issuer");
        assert_eq!(decoded.sub, Some("test-subject".to_string()));
    }

    #[test]
    fn test_decode_header() {
        let secret = b"secret";
        let claims = Claims::new("test", 3600);

        let token = sign_hs256(&claims, secret).unwrap();
        let header = decode_header(&token).unwrap();

        assert_eq!(header.alg, Algorithm::HS256);
    }
}
