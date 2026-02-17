//! Cryptography utilities for AT Protocol.
//!
//! This module provides Secp256k1 key management and signing operations
//! used for repository commits and service authentication.

use k256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::cid::base64url_encode;
use crate::error::Error;

/// A Secp256k1 key pair for signing operations.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generates a new random key pair.
    #[must_use]
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    /// Creates a key pair from a private key bytes (32 bytes).
    ///
    /// # Errors
    /// Returns an error if the key bytes are invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| Error::Crypto(format!("invalid private key: {e}")))?;
        Ok(Self { signing_key })
    }

    /// Creates a key pair from a hex-encoded private key.
    ///
    /// # Errors
    /// Returns an error if the hex string or key is invalid.
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(hex).map_err(|e| Error::Crypto(format!("invalid hex: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// Returns the private key bytes.
    #[must_use]
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    /// Returns the private key as a hex string.
    #[must_use]
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key_bytes())
    }

    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: *self.signing_key.verifying_key(),
        }
    }

    /// Signs data with this key pair.
    ///
    /// # Errors
    /// Returns an error if signing fails.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Returns the public key as a multibase-encoded string (for DID documents).
    #[must_use]
    pub fn public_key_multibase(&self) -> String {
        self.public_key().to_multibase()
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public_key", &self.public_key().to_multibase())
            .finish_non_exhaustive()
    }
}

/// A Secp256k1 public key for verification.
#[derive(Clone)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl PublicKey {
    /// Creates a public key from compressed bytes (33 bytes).
    ///
    /// # Errors
    /// Returns an error if the key bytes are invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| Error::Crypto(format!("invalid public key: {e}")))?;
        Ok(Self { verifying_key })
    }

    /// Creates a public key from a multibase-encoded string.
    ///
    /// # Errors
    /// Returns an error if the multibase or key is invalid.
    pub fn from_multibase(s: &str) -> Result<Self, Error> {
        // Multikey format: multicodec prefix + key bytes
        let (_, bytes) =
            multibase::decode(s).map_err(|e| Error::Crypto(format!("invalid multibase: {e}")))?;

        // Skip the multicodec prefix (0xe7 0x01 for secp256k1-pub)
        if bytes.len() < 2 {
            return Err(Error::Crypto("multikey too short".into()));
        }

        // The prefix for secp256k1-pub is 0xe7 0x01
        if bytes[0] == 0xe7 && bytes[1] == 0x01 {
            Self::from_bytes(&bytes[2..])
        } else {
            // Try without prefix
            Self::from_bytes(&bytes)
        }
    }

    /// Returns the compressed public key bytes (33 bytes).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.verifying_key
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Returns the public key as a multibase-encoded string.
    #[must_use]
    pub fn to_multibase(&self) -> String {
        let mut bytes = vec![0xe7, 0x01]; // secp256k1-pub multicodec prefix
        bytes.extend_from_slice(&self.to_bytes());
        multibase::encode(multibase::Base::Base58Btc, &bytes)
    }

    /// Verifies a signature against this public key.
    ///
    /// # Errors
    /// Returns an error if verification fails.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| Error::Crypto(format!("invalid signature: {e}")))?;

        self.verifying_key
            .verify(data, &sig)
            .map_err(|e| Error::Crypto(format!("verification failed: {e}")))
    }

    /// Returns the JWK thumbprint for `DPoP` binding.
    ///
    /// # Panics
    ///
    /// This function will not panic as the public key is always valid.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn jwk_thumbprint(&self) -> String {
        use crate::cid::sha256;

        let point = self.verifying_key.to_encoded_point(false);
        // Safety: Uncompressed points always have x and y coordinates
        let x = base64url_encode(point.x().expect("uncompressed point has x").as_slice());
        let y = base64url_encode(point.y().expect("uncompressed point has y").as_slice());

        // JWK thumbprint is SHA-256 of the canonical JSON
        let jwk_json = format!(r#"{{"crv":"secp256k1","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let hash = sha256(jwk_json.as_bytes());
        base64url_encode(&hash)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("multibase", &self.to_multibase())
            .finish()
    }
}

/// JWK (JSON Web Key) representation for ES256K keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (always "EC" for elliptic curve).
    pub kty: String,
    /// Curve name (always "secp256k1" for ES256K).
    pub crv: String,
    /// X coordinate (base64url-encoded).
    pub x: String,
    /// Y coordinate (base64url-encoded).
    pub y: String,
    /// Private key D value (base64url-encoded, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl Jwk {
    /// Creates a JWK from a public key.
    ///
    /// # Panics
    ///
    /// This function will not panic as the public key is always valid.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn from_public_key(public_key: &PublicKey) -> Self {
        let point = public_key.verifying_key.to_encoded_point(false);
        // Safety: Uncompressed points always have x and y coordinates
        Self {
            kty: "EC".to_string(),
            crv: "secp256k1".to_string(),
            x: base64url_encode(point.x().expect("uncompressed point has x").as_slice()),
            y: base64url_encode(point.y().expect("uncompressed point has y").as_slice()),
            d: None,
        }
    }

    /// Creates a JWK from a key pair (includes private key).
    #[must_use]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let mut jwk = Self::from_public_key(&keypair.public_key());
        jwk.d = Some(base64url_encode(&keypair.private_key_bytes()));
        jwk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key();

        assert!(!keypair.private_key_hex().is_empty());
        assert!(!public_key.to_multibase().is_empty());
    }

    #[test]
    fn test_keypair_from_hex() {
        let keypair = Keypair::generate();
        let hex = keypair.private_key_hex();

        let restored = Keypair::from_hex(&hex).unwrap();
        assert_eq!(
            keypair.public_key().to_multibase(),
            restored.public_key().to_multibase()
        );
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate();
        let data = b"hello world";

        let signature = keypair.sign(data).unwrap();
        keypair.public_key().verify(data, &signature).unwrap();
    }

    #[test]
    fn test_verify_wrong_data() {
        let keypair = Keypair::generate();
        let data = b"hello world";
        let wrong_data = b"wrong data";

        let signature = keypair.sign(data).unwrap();
        assert!(keypair.public_key().verify(wrong_data, &signature).is_err());
    }

    #[test]
    fn test_public_key_multibase_roundtrip() {
        let keypair = Keypair::generate();
        let multibase = keypair.public_key().to_multibase();

        let restored = PublicKey::from_multibase(&multibase).unwrap();
        assert_eq!(keypair.public_key().to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_jwk_from_public_key() {
        let keypair = Keypair::generate();
        let jwk = Jwk::from_public_key(&keypair.public_key());

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "secp256k1");
        assert!(jwk.d.is_none());
    }

    #[test]
    fn test_jwk_from_keypair() {
        let keypair = Keypair::generate();
        let jwk = Jwk::from_keypair(&keypair);

        assert!(jwk.d.is_some());
    }

    #[test]
    fn test_jwk_thumbprint() {
        let keypair = Keypair::generate();
        let thumbprint = keypair.public_key().jwk_thumbprint();

        // JWK thumbprint should be base64url-encoded SHA-256 (43 chars)
        assert_eq!(thumbprint.len(), 43);
    }
}
