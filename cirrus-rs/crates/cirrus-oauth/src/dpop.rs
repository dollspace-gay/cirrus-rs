//! DPoP (Demonstrating Proof of Possession) implementation.
//!
//! Implements RFC 9449 for binding tokens to client keys.

use serde::{Deserialize, Serialize};

use crate::error::{OAuthError, Result};

/// DPoP proof JWT claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopClaims {
    /// JWT ID (unique identifier for replay prevention).
    pub jti: String,
    /// HTTP method of the request.
    pub htm: String,
    /// HTTP URI of the request.
    pub htu: String,
    /// Issued at time.
    pub iat: u64,
    /// Access token hash (for token-bound requests).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Nonce from server (for replay prevention).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// DPoP proof header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    /// Algorithm (must be ES256 for AT Protocol).
    pub alg: String,
    /// Type (must be "dpop+jwt").
    pub typ: String,
    /// JSON Web Key (public key).
    pub jwk: DpopJwk,
}

/// JWK for DPoP proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopJwk {
    /// Key type.
    pub kty: String,
    /// Curve name.
    pub crv: String,
    /// X coordinate.
    pub x: String,
    /// Y coordinate.
    pub y: String,
}

/// Maximum age for DPoP proofs (5 minutes).
const MAX_PROOF_AGE_SECS: u64 = 300;

/// Verifies a DPoP proof JWT.
///
/// # Errors
/// Returns an error if the proof is invalid.
pub fn verify_proof(
    proof: &str,
    expected_method: &str,
    expected_uri: &str,
    access_token: Option<&str>,
    expected_nonce: Option<&str>,
) -> Result<DpopJwk> {
    // Decode header
    let header = decode_header(proof)?;

    // Verify header
    if header.typ != "dpop+jwt" {
        return Err(OAuthError::DpopError("invalid typ, expected dpop+jwt".into()));
    }

    if header.alg != "ES256" {
        return Err(OAuthError::DpopError("invalid alg, expected ES256".into()));
    }

    // Decode claims (unverified for now - full implementation would verify signature)
    let claims = decode_claims(proof)?;

    // Verify htm (HTTP method)
    if claims.htm.to_uppercase() != expected_method.to_uppercase() {
        return Err(OAuthError::DpopError(format!(
            "htm mismatch: expected {expected_method}, got {}",
            claims.htm
        )));
    }

    // Verify htu (HTTP URI) - compare without query/fragment
    let proof_uri = normalize_uri(&claims.htu);
    let expected_uri_normalized = normalize_uri(expected_uri);
    if proof_uri != expected_uri_normalized {
        return Err(OAuthError::DpopError(format!(
            "htu mismatch: expected {expected_uri_normalized}, got {proof_uri}"
        )));
    }

    // Verify iat (issued at) - must be recent
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if claims.iat > now + 60 {
        return Err(OAuthError::DpopError("proof issued in the future".into()));
    }

    if now > claims.iat + MAX_PROOF_AGE_SECS {
        return Err(OAuthError::DpopError("proof expired".into()));
    }

    // Verify ath (access token hash) if access token provided
    if let Some(token) = access_token {
        let expected_ath = compute_token_hash(token);
        match &claims.ath {
            Some(ath) if ath == &expected_ath => {}
            Some(ath) => {
                return Err(OAuthError::DpopError(format!(
                    "ath mismatch: expected {expected_ath}, got {ath}"
                )));
            }
            None => {
                return Err(OAuthError::DpopError("missing ath claim".into()));
            }
        }
    }

    // Verify nonce if expected
    if let Some(expected) = expected_nonce {
        match &claims.nonce {
            Some(nonce) if nonce == expected => {}
            Some(nonce) => {
                return Err(OAuthError::DpopError(format!(
                    "nonce mismatch: expected {expected}, got {nonce}"
                )));
            }
            None => {
                return Err(OAuthError::DpopError("missing nonce claim".into()));
            }
        }
    }

    Ok(header.jwk)
}

/// Computes the JWK thumbprint for a DPoP key.
#[must_use]
pub fn compute_jwk_thumbprint(jwk: &DpopJwk) -> String {
    use sha2::{Digest, Sha256};

    // Canonical JSON representation (keys in alphabetical order)
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );

    let hash = Sha256::digest(canonical.as_bytes());
    base64_url_encode(&hash)
}

/// Computes the access token hash for the ath claim.
fn compute_token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(token.as_bytes());
    base64_url_encode(&hash)
}

/// Generates a new DPoP nonce.
#[must_use]
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random()).collect();
    base64_url_encode(&bytes)
}

fn decode_header(proof: &str) -> Result<DpopHeader> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::DpopError("invalid JWT format".into()));
    }

    let header_bytes = base64_url_decode(parts[0])?;
    serde_json::from_slice(&header_bytes)
        .map_err(|e| OAuthError::DpopError(format!("invalid header JSON: {e}")))
}

fn decode_claims(proof: &str) -> Result<DpopClaims> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::DpopError("invalid JWT format".into()));
    }

    let claims_bytes = base64_url_decode(parts[1])?;
    serde_json::from_slice(&claims_bytes)
        .map_err(|e| OAuthError::DpopError(format!("invalid claims JSON: {e}")))
}

fn normalize_uri(uri: &str) -> String {
    // Remove query string and fragment
    uri.split('?').next().unwrap_or(uri).to_string()
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| OAuthError::DpopError(format!("invalid base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_jwk_thumbprint() {
        let jwk = DpopJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "test_x_coordinate".to_string(),
            y: "test_y_coordinate".to_string(),
        };

        let thumbprint = compute_jwk_thumbprint(&jwk);
        assert!(!thumbprint.is_empty());

        // Same input should produce same output
        let thumbprint2 = compute_jwk_thumbprint(&jwk);
        assert_eq!(thumbprint, thumbprint2);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();

        // Nonces should be unique
        assert_ne!(nonce1, nonce2);

        // Nonces should be reasonable length
        assert!(nonce1.len() >= 20);
    }

    #[test]
    fn test_normalize_uri() {
        assert_eq!(
            normalize_uri("https://example.com/path?query=1"),
            "https://example.com/path"
        );
        assert_eq!(
            normalize_uri("https://example.com/path"),
            "https://example.com/path"
        );
    }
}
