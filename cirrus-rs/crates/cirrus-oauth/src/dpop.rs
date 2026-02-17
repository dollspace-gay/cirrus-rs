//! `DPoP` (Demonstrating Proof of Possession) implementation.
//!
//! Implements RFC 9449 for binding tokens to client keys.

use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{EncodedPoint, PublicKey};
use serde::{Deserialize, Serialize};

use crate::error::{OAuthError, Result};

/// `DPoP` proof JWT claims.
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

/// `DPoP` proof header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    /// Algorithm (must be ES256 for AT Protocol).
    pub alg: String,
    /// Type (must be "dpop+jwt").
    pub typ: String,
    /// JSON Web Key (public key).
    pub jwk: DpopJwk,
}

/// JWK for `DPoP` proofs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopJwk {
    /// Key type.
    pub kty: String,
    /// Curve name.
    pub crv: String,
    /// X coordinate (base64url-encoded).
    pub x: String,
    /// Y coordinate (base64url-encoded).
    pub y: String,
}

impl DpopJwk {
    /// Converts the JWK to a P-256 verifying key.
    ///
    /// # Errors
    /// Returns an error if the JWK contains invalid key data.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey> {
        if self.kty != "EC" {
            return Err(OAuthError::DpopError(format!(
                "unsupported key type: {}, expected EC",
                self.kty
            )));
        }

        if self.crv != "P-256" {
            return Err(OAuthError::DpopError(format!(
                "unsupported curve: {}, expected P-256",
                self.crv
            )));
        }

        let x_bytes = base64_url_decode(&self.x)?;
        let y_bytes = base64_url_decode(&self.y)?;

        // P-256 coordinates are 32 bytes each
        if x_bytes.len() != 32 || y_bytes.len() != 32 {
            return Err(OAuthError::DpopError(
                "invalid key coordinate length".into(),
            ));
        }

        // Create uncompressed point: 0x04 || x || y
        let mut point_bytes = vec![0x04];
        point_bytes.extend_from_slice(&x_bytes);
        point_bytes.extend_from_slice(&y_bytes);

        let encoded_point = EncodedPoint::from_bytes(&point_bytes)
            .map_err(|e| OAuthError::DpopError(format!("invalid encoded point: {e}")))?;

        let public_key = PublicKey::from_encoded_point(&encoded_point);
        if public_key.is_none().into() {
            return Err(OAuthError::DpopError("invalid public key point".into()));
        }

        // Safety: we just checked is_none() above
        #[allow(clippy::unwrap_used)]
        let public_key = public_key.unwrap();

        Ok(VerifyingKey::from(&public_key))
    }
}

/// Maximum age for `DPoP` proofs (5 minutes).
const MAX_PROOF_AGE_SECS: u64 = 300;

/// Verifies a `DPoP` proof JWT including cryptographic signature verification.
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
    // Split JWT parts
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::DpopError("invalid JWT format".into()));
    }

    // Decode header
    let header = decode_header(proof)?;

    // Verify header
    if header.typ != "dpop+jwt" {
        return Err(OAuthError::DpopError(
            "invalid typ, expected dpop+jwt".into(),
        ));
    }

    if header.alg != "ES256" {
        return Err(OAuthError::DpopError("invalid alg, expected ES256".into()));
    }

    // Verify the cryptographic signature
    verify_signature(proof, &header.jwk)?;

    // Decode claims (now verified)
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

/// Verifies the JWT signature using the embedded JWK.
fn verify_signature(proof: &str, jwk: &DpopJwk) -> Result<()> {
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 {
        return Err(OAuthError::DpopError("invalid JWT format".into()));
    }

    // The signed data is header.payload (first two parts)
    let signed_data = format!("{}.{}", parts[0], parts[1]);

    // Decode the signature
    let signature_bytes = base64_url_decode(parts[2])?;

    // Convert JWK to verifying key
    let verifying_key = jwk.to_verifying_key()?;

    // Parse the signature (ES256 produces 64-byte signatures: r || s)
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| OAuthError::DpopError(format!("invalid signature format: {e}")))?;

    // Verify the signature
    verifying_key
        .verify(signed_data.as_bytes(), &signature)
        .map_err(|e| OAuthError::DpopError(format!("signature verification failed: {e}")))?;

    Ok(())
}

/// Computes the JWK thumbprint for a `DPoP` key.
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

/// Generates a new `DPoP` nonce.
#[must_use]
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
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

/// A P-256 key pair for creating `DPoP` proofs.
pub struct DpopKeyPair {
    signing_key: p256::ecdsa::SigningKey,
}

impl DpopKeyPair {
    /// Generates a new random `DPoP` key pair.
    #[must_use]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    /// Returns the public key as a `DpopJwk`.
    #[must_use]
    pub fn public_jwk(&self) -> DpopJwk {
        let public_key = self.signing_key.verifying_key();
        let point = public_key.to_encoded_point(false);

        DpopJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: base64_url_encode(point.x().map(|x| x.as_slice()).unwrap_or(&[])),
            y: base64_url_encode(point.y().map(|y| y.as_slice()).unwrap_or(&[])),
        }
    }

    /// Returns the JWK thumbprint for this key.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        compute_jwk_thumbprint(&self.public_jwk())
    }

    /// Creates a `DPoP` proof JWT.
    ///
    /// # Errors
    /// Returns an error if proof creation fails.
    pub fn create_proof(
        &self,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
        nonce: Option<&str>,
    ) -> Result<String> {
        use p256::ecdsa::signature::Signer;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Create header
        let header = DpopHeader {
            alg: "ES256".to_string(),
            typ: "dpop+jwt".to_string(),
            jwk: self.public_jwk(),
        };

        // Create claims
        let claims = DpopClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: method.to_uppercase(),
            htu: uri.to_string(),
            iat: now,
            ath: access_token.map(compute_token_hash),
            nonce: nonce.map(String::from),
        };

        // Encode header and claims
        let header_json = serde_json::to_string(&header)
            .map_err(|e| OAuthError::DpopError(format!("failed to serialize header: {e}")))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| OAuthError::DpopError(format!("failed to serialize claims: {e}")))?;

        let header_b64 = base64_url_encode(header_json.as_bytes());
        let claims_b64 = base64_url_encode(claims_json.as_bytes());

        // Sign the payload
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_b64 = base64_url_encode(&signature.to_bytes());

        Ok(format!("{signing_input}.{signature_b64}"))
    }
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

    #[test]
    fn test_keypair_generation() {
        let keypair = DpopKeyPair::generate();
        let jwk = keypair.public_jwk();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(!jwk.y.is_empty());
    }

    #[test]
    fn test_create_and_verify_proof() {
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof("POST", "https://example.com/token", None, None)
            .expect("failed to create proof");

        let result = verify_proof(&proof, "POST", "https://example.com/token", None, None);
        assert!(result.is_ok());

        let verified_jwk = result.expect("verification failed");
        assert_eq!(verified_jwk, keypair.public_jwk());
    }

    #[test]
    fn test_proof_with_access_token() {
        let keypair = DpopKeyPair::generate();
        let access_token = "test_access_token_123";

        let proof = keypair
            .create_proof(
                "GET",
                "https://example.com/resource",
                Some(access_token),
                None,
            )
            .expect("failed to create proof");

        let result = verify_proof(
            &proof,
            "GET",
            "https://example.com/resource",
            Some(access_token),
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_with_nonce() {
        let keypair = DpopKeyPair::generate();
        let nonce = generate_nonce();

        let proof = keypair
            .create_proof("POST", "https://example.com/token", None, Some(&nonce))
            .expect("failed to create proof");

        let result = verify_proof(
            &proof,
            "POST",
            "https://example.com/token",
            None,
            Some(&nonce),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_proof_wrong_method() {
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof("POST", "https://example.com/token", None, None)
            .expect("failed to create proof");

        // Try to verify with wrong method
        let result = verify_proof(&proof, "GET", "https://example.com/token", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("htm mismatch"));
    }

    #[test]
    fn test_proof_wrong_uri() {
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof("POST", "https://example.com/token", None, None)
            .expect("failed to create proof");

        // Try to verify with wrong URI
        let result = verify_proof(&proof, "POST", "https://other.com/token", None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("htu mismatch"));
    }

    #[test]
    fn test_proof_wrong_access_token() {
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof("GET", "https://example.com/resource", Some("token_a"), None)
            .expect("failed to create proof");

        // Try to verify with different access token
        let result = verify_proof(
            &proof,
            "GET",
            "https://example.com/resource",
            Some("token_b"),
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ath mismatch"));
    }

    #[test]
    fn test_proof_signature_tampering() {
        let keypair = DpopKeyPair::generate();
        let proof = keypair
            .create_proof("POST", "https://example.com/token", None, None)
            .expect("failed to create proof");

        // Tamper with the signature
        let parts: Vec<&str> = proof.split('.').collect();
        let tampered_proof = format!("{}.{}.AAAA{}", parts[0], parts[1], &parts[2][4..]);

        let result = verify_proof(
            &tampered_proof,
            "POST",
            "https://example.com/token",
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_thumbprint_consistency() {
        let keypair = DpopKeyPair::generate();
        let thumbprint1 = keypair.thumbprint();
        let thumbprint2 = compute_jwk_thumbprint(&keypair.public_jwk());

        assert_eq!(thumbprint1, thumbprint2);
    }
}
