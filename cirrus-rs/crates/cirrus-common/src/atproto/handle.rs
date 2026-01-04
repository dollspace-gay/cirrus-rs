//! Handle type and validation.
//!
//! Handles are user-facing identifiers in the AT Protocol, formatted as domain names.
//! Examples: `alice.bsky.social`, `bob.example.com`

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// Maximum length for a handle.
const MAX_HANDLE_LENGTH: usize = 253;

/// A validated AT Protocol handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Handle(String);

impl Handle {
    /// Creates a new Handle from a string, validating the format.
    ///
    /// # Errors
    /// Returns an error if the handle format is invalid.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// Validates a handle string.
    ///
    /// # Errors
    /// Returns an error if the handle format is invalid.
    pub fn validate(s: &str) -> Result<(), Error> {
        if s.is_empty() {
            return Err(Error::InvalidHandle("handle cannot be empty".into()));
        }

        if s.len() > MAX_HANDLE_LENGTH {
            return Err(Error::InvalidHandle(format!(
                "handle exceeds maximum length of {MAX_HANDLE_LENGTH}"
            )));
        }

        // Must contain at least one dot (domain format)
        if !s.contains('.') {
            return Err(Error::InvalidHandle(
                "handle must be a valid domain with at least one dot".into(),
            ));
        }

        // Cannot start or end with a dot
        if s.starts_with('.') || s.ends_with('.') {
            return Err(Error::InvalidHandle(
                "handle cannot start or end with a dot".into(),
            ));
        }

        // Validate each label
        for label in s.split('.') {
            Self::validate_label(label)?;
        }

        Ok(())
    }

    fn validate_label(label: &str) -> Result<(), Error> {
        if label.is_empty() {
            return Err(Error::InvalidHandle("empty label in handle".into()));
        }

        if label.len() > 63 {
            return Err(Error::InvalidHandle(
                "label exceeds maximum length of 63".into(),
            ));
        }

        // Cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidHandle(
                "label cannot start or end with hyphen".into(),
            ));
        }

        // Must contain only alphanumeric characters and hyphens
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(Error::InvalidHandle(
                "label must contain only alphanumeric characters and hyphens".into(),
            ));
        }

        Ok(())
    }

    /// Returns the handle string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the TLD (top-level domain) of the handle.
    #[must_use]
    pub fn tld(&self) -> Option<&str> {
        self.0.rsplit('.').next()
    }

    /// Normalizes the handle to lowercase.
    #[must_use]
    pub fn normalize(&self) -> Self {
        Self(self.0.to_ascii_lowercase())
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Handle {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_handle() {
        let handle = Handle::new("alice.bsky.social").unwrap();
        assert_eq!(handle.as_str(), "alice.bsky.social");
        assert_eq!(handle.tld(), Some("social"));
    }

    #[test]
    fn test_valid_handle_with_numbers() {
        let handle = Handle::new("user123.example.com").unwrap();
        assert_eq!(handle.as_str(), "user123.example.com");
    }

    #[test]
    fn test_valid_handle_with_hyphens() {
        let handle = Handle::new("my-user.my-domain.com").unwrap();
        assert_eq!(handle.as_str(), "my-user.my-domain.com");
    }

    #[test]
    fn test_invalid_handle_no_dot() {
        assert!(Handle::new("nodothandle").is_err());
    }

    #[test]
    fn test_invalid_handle_starts_with_dot() {
        assert!(Handle::new(".example.com").is_err());
    }

    #[test]
    fn test_invalid_handle_ends_with_dot() {
        assert!(Handle::new("example.com.").is_err());
    }

    #[test]
    fn test_invalid_handle_label_starts_with_hyphen() {
        assert!(Handle::new("-user.example.com").is_err());
    }

    #[test]
    fn test_invalid_handle_empty() {
        assert!(Handle::new("").is_err());
    }

    #[test]
    fn test_handle_normalize() {
        let handle = Handle::new("Alice.BSKY.Social").unwrap();
        let normalized = handle.normalize();
        assert_eq!(normalized.as_str(), "alice.bsky.social");
    }

    #[test]
    fn test_handle_from_str() {
        let handle: Handle = "bob.example.com".parse().unwrap();
        assert_eq!(handle.tld(), Some("com"));
    }
}
