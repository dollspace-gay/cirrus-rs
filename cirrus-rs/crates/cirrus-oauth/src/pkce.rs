//! PKCE (Proof Key for Code Exchange) implementation.
//!
//! Implements RFC 7636 with S256 method.

use sha2::{Digest, Sha256};

use crate::error::{OAuthError, Result};

/// Minimum length for a code verifier.
const MIN_VERIFIER_LENGTH: usize = 43;

/// Maximum length for a code verifier.
const MAX_VERIFIER_LENGTH: usize = 128;

/// Verifies a PKCE code challenge against a code verifier.
///
/// # Errors
/// Returns an error if the verifier format is invalid or doesn't match the challenge.
pub fn verify_challenge(code_verifier: &str, code_challenge: &str) -> Result<()> {
    // Validate verifier length
    if code_verifier.len() < MIN_VERIFIER_LENGTH {
        return Err(OAuthError::PkceError(format!(
            "code verifier too short (min {MIN_VERIFIER_LENGTH})"
        )));
    }

    if code_verifier.len() > MAX_VERIFIER_LENGTH {
        return Err(OAuthError::PkceError(format!(
            "code verifier too long (max {MAX_VERIFIER_LENGTH})"
        )));
    }

    // Validate verifier characters (RFC 7636: unreserved characters)
    if !code_verifier
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
    {
        return Err(OAuthError::PkceError(
            "code verifier contains invalid characters".into(),
        ));
    }

    // Compute S256 challenge from verifier
    let computed_challenge = compute_s256_challenge(code_verifier);

    // Compare challenges
    if computed_challenge != code_challenge {
        return Err(OAuthError::PkceError("code challenge mismatch".into()));
    }

    Ok(())
}

/// Computes the S256 code challenge from a code verifier.
///
/// S256: BASE64URL(SHA256(code_verifier))
#[must_use]
pub fn compute_s256_challenge(code_verifier: &str) -> String {
    let hash = Sha256::digest(code_verifier.as_bytes());
    base64_url_encode(&hash)
}

/// Generates a random code verifier.
#[must_use]
pub fn generate_verifier() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
    base64_url_encode(&bytes)
}

/// Encodes bytes as base64url without padding.
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_challenge_success() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = compute_s256_challenge(verifier);

        assert!(verify_challenge(verifier, &challenge).is_ok());
    }

    #[test]
    fn test_verify_challenge_mismatch() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "wrong_challenge_value_here_12345678901234567";

        assert!(verify_challenge(verifier, wrong_challenge).is_err());
    }

    #[test]
    fn test_verifier_too_short() {
        let short_verifier = "tooshort";
        let challenge = "doesnt_matter";

        let result = verify_challenge(short_verifier, challenge);
        assert!(matches!(result, Err(OAuthError::PkceError(_))));
    }

    #[test]
    fn test_verifier_invalid_chars() {
        let invalid_verifier = "valid_prefix_but_has_invalid_chars_@#$%^&*()_1234567890";
        let challenge = "doesnt_matter";

        let result = verify_challenge(invalid_verifier, challenge);
        assert!(matches!(result, Err(OAuthError::PkceError(_))));
    }

    #[test]
    fn test_generate_verifier() {
        let verifier = generate_verifier();

        // Should be valid length
        assert!(verifier.len() >= MIN_VERIFIER_LENGTH);

        // Should be valid characters
        assert!(verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_s256_challenge_deterministic() {
        let verifier = "test_verifier_that_is_long_enough_for_pkce_requirements";
        let challenge1 = compute_s256_challenge(verifier);
        let challenge2 = compute_s256_challenge(verifier);

        assert_eq!(challenge1, challenge2);
    }
}
