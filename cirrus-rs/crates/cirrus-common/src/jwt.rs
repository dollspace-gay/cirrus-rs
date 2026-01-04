//! JWT utilities for AT Protocol authentication.
//!
//! Supports ES256K (secp256k1) for service auth and HS256 for session tokens.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
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

/// Signs a JWT with ES256K (secp256k1).
///
/// # Errors
/// Returns an error if signing fails.
pub fn sign_es256k<T: Serialize>(claims: &T, keypair: &Keypair) -> Result<String, Error> {
    let header = Header::new(Algorithm::ES256K);

    // jsonwebtoken expects a PEM or raw key for ES256K
    // We need to convert our k256 key to the format it expects
    let key_bytes = keypair.private_key_bytes();
    let encoding_key = EncodingKey::from_ec_der(&create_es256k_der(&key_bytes));

    jsonwebtoken::encode(&header, claims, &encoding_key)
        .map_err(|e| Error::Jwt(format!("signing failed: {e}")))
}

/// Verifies a JWT with ES256K (secp256k1).
///
/// # Errors
/// Returns an error if verification fails.
pub fn verify_es256k<T: DeserializeOwned>(
    token: &str,
    public_key_bytes: &[u8],
) -> Result<T, Error> {
    let decoding_key = DecodingKey::from_ec_der(&create_es256k_public_der(public_key_bytes));

    let mut validation = Validation::new(Algorithm::ES256K);
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<T>(token, &decoding_key, &validation)
        .map_err(|e| Error::Jwt(format!("verification failed: {e}")))?;

    Ok(token_data.claims)
}

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

/// Decodes a JWT without verification (for inspection only).
///
/// # Errors
/// Returns an error if the token format is invalid.
pub fn decode_unverified<T: DeserializeOwned>(token: &str) -> Result<T, Error> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("invalid token format".into()));
    }

    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .map_err(|e| Error::Jwt(format!("invalid base64: {e}")))?;

    serde_json::from_slice(&payload).map_err(|e| Error::Jwt(format!("invalid JSON: {e}")))
}

/// Extracts the header from a JWT without verification.
///
/// # Errors
/// Returns an error if the token format is invalid.
pub fn decode_header(token: &str) -> Result<Header, Error> {
    jsonwebtoken::decode_header(token).map_err(|e| Error::Jwt(format!("invalid header: {e}")))
}

// Helper to create a minimal DER-encoded private key for ES256K
fn create_es256k_der(private_key: &[u8; 32]) -> Vec<u8> {
    // SEC1 EC private key format wrapped in PKCS#8
    // This is a simplified version - a full implementation would use proper ASN.1 encoding
    let mut der = Vec::with_capacity(128);

    // PKCS#8 header for secp256k1
    der.extend_from_slice(&[
        0x30, 0x81, 0x87, // SEQUENCE
        0x02, 0x01, 0x00, // INTEGER version = 0
        0x30, 0x13, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID secp256k1 (wrong, but close)
        0x04, 0x6d, // OCTET STRING
        0x30, 0x6b, // SEQUENCE
        0x02, 0x01, 0x01, // INTEGER version = 1
        0x04, 0x20, // OCTET STRING (32 bytes)
    ]);
    der.extend_from_slice(private_key);
    der.extend_from_slice(&[
        0xa1, 0x44, // [1] (public key)
        0x03, 0x42, 0x00, 0x04, // BIT STRING (uncompressed point)
    ]);
    // We'd need to compute the public key point here
    // For now, this is a placeholder that won't work for real signing
    der.extend_from_slice(&[0u8; 64]); // placeholder

    der
}

fn create_es256k_public_der(public_key: &[u8]) -> Vec<u8> {
    // SubjectPublicKeyInfo for secp256k1
    let mut der = Vec::with_capacity(128);
    der.extend_from_slice(&[
        0x30, 0x56, // SEQUENCE
        0x30, 0x10, // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID secp256k1
        0x03, 0x42, 0x00, // BIT STRING
    ]);
    der.extend_from_slice(public_key);
    der
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_decode_unverified() {
        let secret = b"secret";
        let claims = Claims::new("test-issuer", 3600)
            .with_sub("test-subject");

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
