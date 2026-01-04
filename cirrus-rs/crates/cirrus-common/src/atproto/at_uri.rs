//! AT URI type and parsing.
//!
//! AT URIs identify records in the AT Protocol. Format: `at://<authority>/<collection>/<rkey>`
//! Example: `at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jzfcijpj2z2a`

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use super::{Did, Handle};
use crate::error::Error;

/// The authority component of an AT URI (either a DID or Handle).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Authority {
    /// A DID authority.
    Did(Did),
    /// A handle authority.
    Handle(Handle),
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Did(did) => write!(f, "{did}"),
            Self::Handle(handle) => write!(f, "{handle}"),
        }
    }
}

/// A validated AT Protocol URI.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AtUri(String);

impl AtUri {
    /// Creates a new AT URI from a string, validating the format.
    ///
    /// # Errors
    /// Returns an error if the AT URI format is invalid.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// Creates an AT URI from components.
    #[must_use]
    pub fn make(authority: &str, collection: &str, rkey: &str) -> Self {
        Self(format!("at://{authority}/{collection}/{rkey}"))
    }

    /// Creates an AT URI for a collection (without rkey).
    #[must_use]
    pub fn for_collection(authority: &str, collection: &str) -> Self {
        Self(format!("at://{authority}/{collection}"))
    }

    /// Creates an AT URI for just an authority.
    #[must_use]
    pub fn authority_only(authority: &str) -> Self {
        Self(format!("at://{authority}"))
    }

    /// Validates an AT URI string.
    ///
    /// # Errors
    /// Returns an error if the AT URI format is invalid.
    pub fn validate(s: &str) -> Result<(), Error> {
        if !s.starts_with("at://") {
            return Err(Error::InvalidAtUri("must start with 'at://'".into()));
        }

        let rest = &s[5..];
        if rest.is_empty() {
            return Err(Error::InvalidAtUri("authority cannot be empty".into()));
        }

        // Parse authority
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        let authority = parts[0];

        // Validate authority is either a DID or handle
        if authority.starts_with("did:") {
            Did::validate(authority)?;
        } else {
            Handle::validate(authority)?;
        }

        // If there's a path, validate collection and optional rkey
        if parts.len() > 1 && !parts[1].is_empty() {
            let path_parts: Vec<&str> = parts[1].splitn(2, '/').collect();
            let collection = path_parts[0];

            // Collection should be an NSID (Namespaced Identifier)
            if !Self::is_valid_nsid(collection) {
                return Err(Error::InvalidAtUri(format!(
                    "invalid collection NSID: {collection}"
                )));
            }

            // Rkey validation is lenient - just check it's not empty if present
            if path_parts.len() > 1 && path_parts[1].is_empty() {
                return Err(Error::InvalidAtUri("rkey cannot be empty if present".into()));
            }
        }

        Ok(())
    }

    fn is_valid_nsid(s: &str) -> bool {
        // NSID format: segments separated by dots, last segment is the name
        // Example: app.bsky.feed.post
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() < 3 {
            return false;
        }

        for part in &parts {
            if part.is_empty() {
                return false;
            }
            // Each segment must start with a letter and contain only alphanumeric chars
            let first = part.chars().next().unwrap_or('0');
            if !first.is_ascii_alphabetic() {
                return false;
            }
            if !part.chars().all(|c| c.is_ascii_alphanumeric()) {
                return false;
            }
        }

        true
    }

    /// Returns the full AT URI string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the authority part of the URI.
    #[must_use]
    pub fn authority_str(&self) -> &str {
        let rest = &self.0[5..]; // Skip "at://"
        rest.split('/').next().unwrap_or("")
    }

    /// Parses and returns the authority as either a DID or Handle.
    ///
    /// # Errors
    /// Returns an error if the authority cannot be parsed.
    pub fn authority(&self) -> Result<Authority, Error> {
        let auth = self.authority_str();
        if auth.starts_with("did:") {
            Ok(Authority::Did(Did::new(auth)?))
        } else {
            Ok(Authority::Handle(Handle::new(auth)?))
        }
    }

    /// Returns the collection part of the URI, if present.
    #[must_use]
    pub fn collection(&self) -> Option<&str> {
        let rest = &self.0[5..]; // Skip "at://"
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() > 1 && !parts[1].is_empty() {
            Some(parts[1])
        } else {
            None
        }
    }

    /// Returns the record key part of the URI, if present.
    #[must_use]
    pub fn rkey(&self) -> Option<&str> {
        let rest = &self.0[5..]; // Skip "at://"
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() > 2 && !parts[2].is_empty() {
            Some(parts[2])
        } else {
            None
        }
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AtUri {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for AtUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_at_uri_full() {
        let uri =
            AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jzfcijpj2z2a")
                .unwrap();
        assert_eq!(uri.authority_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
        assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
        assert_eq!(uri.rkey(), Some("3jzfcijpj2z2a"));
    }

    #[test]
    fn test_valid_at_uri_collection_only() {
        let uri = AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post").unwrap();
        assert_eq!(uri.collection(), Some("app.bsky.feed.post"));
        assert_eq!(uri.rkey(), None);
    }

    #[test]
    fn test_valid_at_uri_authority_only() {
        let uri = AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(uri.authority_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
        assert_eq!(uri.collection(), None);
        assert_eq!(uri.rkey(), None);
    }

    #[test]
    fn test_valid_at_uri_with_handle() {
        let uri = AtUri::new("at://alice.bsky.social/app.bsky.feed.post/abc123").unwrap();
        assert_eq!(uri.authority_str(), "alice.bsky.social");
        assert!(matches!(uri.authority(), Ok(Authority::Handle(_))));
    }

    #[test]
    fn test_at_uri_make() {
        let uri = AtUri::make(
            "did:plc:z72i7hdynmk6r22z27h6tvur",
            "app.bsky.feed.post",
            "3jzfcijpj2z2a",
        );
        assert_eq!(
            uri.as_str(),
            "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jzfcijpj2z2a"
        );
    }

    #[test]
    fn test_invalid_at_uri_no_scheme() {
        assert!(AtUri::new("did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post").is_err());
    }

    #[test]
    fn test_invalid_at_uri_wrong_scheme() {
        assert!(AtUri::new("http://did:plc:z72i7hdynmk6r22z27h6tvur").is_err());
    }

    #[test]
    fn test_invalid_at_uri_bad_collection() {
        assert!(AtUri::new("at://did:plc:z72i7hdynmk6r22z27h6tvur/invalid").is_err());
    }

    #[test]
    fn test_at_uri_from_str() {
        let uri: AtUri = "at://alice.bsky.social/app.bsky.actor.profile/self"
            .parse()
            .unwrap();
        assert_eq!(uri.collection(), Some("app.bsky.actor.profile"));
    }
}
