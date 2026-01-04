//! DID (Decentralized Identifier) type and validation.
//!
//! DIDs in the AT Protocol are either:
//! - `did:plc:*` - PLC directory DIDs
//! - `did:web:*` - Web-based DIDs

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// A validated Decentralized Identifier (DID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Creates a new DID from a string, validating the format.
    ///
    /// # Errors
    /// Returns an error if the DID format is invalid.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// Validates a DID string without creating a new instance.
    ///
    /// # Errors
    /// Returns an error if the DID format is invalid.
    pub fn validate(s: &str) -> Result<(), Error> {
        if !s.starts_with("did:") {
            return Err(Error::InvalidDid("must start with 'did:'".into()));
        }

        let parts: Vec<&str> = s.splitn(3, ':').collect();
        if parts.len() < 3 {
            return Err(Error::InvalidDid("must have method and identifier".into()));
        }

        let method = parts[1];
        let identifier = parts[2];

        match method {
            "plc" => Self::validate_plc_identifier(identifier),
            "web" => Self::validate_web_identifier(identifier),
            _ => Err(Error::InvalidDid(format!("unsupported method: {method}"))),
        }
    }

    fn validate_plc_identifier(id: &str) -> Result<(), Error> {
        // PLC identifiers are base32-encoded, typically 24 characters
        if id.is_empty() {
            return Err(Error::InvalidDid("PLC identifier cannot be empty".into()));
        }
        if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(Error::InvalidDid(
                "PLC identifier must be alphanumeric".into(),
            ));
        }
        Ok(())
    }

    fn validate_web_identifier(id: &str) -> Result<(), Error> {
        // Web DIDs use domain names, optionally with path
        if id.is_empty() {
            return Err(Error::InvalidDid("web identifier cannot be empty".into()));
        }
        // Basic domain validation - must contain at least one dot or be localhost
        if !id.contains('.') && !id.starts_with("localhost") {
            return Err(Error::InvalidDid(
                "web identifier must be a valid domain".into(),
            ));
        }
        Ok(())
    }

    /// Returns the DID method (e.g., "plc" or "web").
    #[must_use]
    pub fn method(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }

    /// Returns the DID identifier (the part after the method).
    #[must_use]
    pub fn identifier(&self) -> &str {
        self.0.splitn(3, ':').nth(2).unwrap_or("")
    }

    /// Returns the full DID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks if this is a PLC DID.
    #[must_use]
    pub fn is_plc(&self) -> bool {
        self.method() == "plc"
    }

    /// Checks if this is a web DID.
    #[must_use]
    pub fn is_web(&self) -> bool {
        self.method() == "web"
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Did {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_plc_did() {
        let did = Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.method(), "plc");
        assert_eq!(did.identifier(), "z72i7hdynmk6r22z27h6tvur");
        assert!(did.is_plc());
        assert!(!did.is_web());
    }

    #[test]
    fn test_valid_web_did() {
        let did = Did::new("did:web:example.com").unwrap();
        assert_eq!(did.method(), "web");
        assert_eq!(did.identifier(), "example.com");
        assert!(!did.is_plc());
        assert!(did.is_web());
    }

    #[test]
    fn test_invalid_did_no_prefix() {
        assert!(Did::new("plc:z72i7hdynmk6r22z27h6tvur").is_err());
    }

    #[test]
    fn test_invalid_did_no_method() {
        assert!(Did::new("did:").is_err());
    }

    #[test]
    fn test_invalid_did_unsupported_method() {
        assert!(Did::new("did:key:z6MkhaXgBZD").is_err());
    }

    #[test]
    fn test_did_display() {
        let did = Did::new("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.to_string(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn test_did_from_str() {
        let did: Did = "did:web:bsky.social".parse().unwrap();
        assert!(did.is_web());
    }
}
