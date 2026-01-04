//! DID resolution and caching.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::error::{PdsError, Result};

/// DID document structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    /// Context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID.
    pub id: String,
    /// Also known as (handles).
    #[serde(rename = "alsoKnownAs", default)]
    pub also_known_as: Vec<String>,
    /// Verification methods (keys).
    #[serde(rename = "verificationMethod", default)]
    pub verification_method: Vec<VerificationMethod>,
    /// Services.
    #[serde(default)]
    pub service: Vec<Service>,
}

/// Verification method (key) in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Key ID.
    pub id: String,
    /// Key type.
    #[serde(rename = "type")]
    pub key_type: String,
    /// Controller DID.
    pub controller: String,
    /// Public key in multibase format.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Service in a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service ID.
    pub id: String,
    /// Service type.
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URL.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Creates a DID document for a PDS.
#[must_use]
pub fn create_did_document(
    did: &str,
    handle: &str,
    pds_endpoint: &str,
    public_key_multibase: &str,
) -> DidDocument {
    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/multikey/v1".to_string(),
            "https://w3id.org/security/suites/secp256k1-2019/v1".to_string(),
        ],
        id: did.to_string(),
        also_known_as: vec![format!("at://{handle}")],
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            key_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase: public_key_multibase.to_string(),
        }],
        service: vec![Service {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: pds_endpoint.to_string(),
        }],
    }
}

/// DID resolver with caching.
pub struct DidResolver {
    cache: RwLock<HashMap<String, CachedDoc>>,
    cache_ttl: Duration,
    http_timeout: Duration,
}

struct CachedDoc {
    doc: DidDocument,
    cached_at: Instant,
}

impl Default for DidResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DidResolver {
    /// Creates a new DID resolver with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300), // 5 minutes
            http_timeout: Duration::from_secs(3),
        }
    }

    /// Creates a resolver with custom TTL and timeout.
    #[must_use]
    pub fn with_config(cache_ttl: Duration, http_timeout: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            cache_ttl,
            http_timeout,
        }
    }

    /// Resolves a DID to its document.
    ///
    /// # Errors
    /// Returns an error if resolution fails.
    pub async fn resolve(&self, did: &str) -> Result<DidDocument> {
        // Check cache first
        if let Some(doc) = self.get_cached(did) {
            return Ok(doc);
        }

        // Resolve based on DID method
        let doc = if did.starts_with("did:web:") {
            self.resolve_web(did).await?
        } else if did.starts_with("did:plc:") {
            self.resolve_plc(did).await?
        } else {
            return Err(PdsError::DidResolution(format!(
                "unsupported DID method: {did}"
            )));
        };

        // Cache the result
        self.cache_doc(did, doc.clone());

        Ok(doc)
    }

    fn get_cached(&self, did: &str) -> Option<DidDocument> {
        let cache = self.cache.read();
        cache.get(did).and_then(|cached| {
            if cached.cached_at.elapsed() < self.cache_ttl {
                Some(cached.doc.clone())
            } else {
                None
            }
        })
    }

    fn cache_doc(&self, did: &str, doc: DidDocument) {
        let mut cache = self.cache.write();
        cache.insert(
            did.to_string(),
            CachedDoc {
                doc,
                cached_at: Instant::now(),
            },
        );
    }

    async fn resolve_web(&self, did: &str) -> Result<DidDocument> {
        let domain = did
            .strip_prefix("did:web:")
            .ok_or_else(|| PdsError::DidResolution("invalid did:web format".into()))?;

        let domain = domain.replace(':', "/");
        let url = format!("https://{domain}/.well-known/did.json");

        let client = reqwest::Client::builder()
            .timeout(self.http_timeout)
            .build()
            .map_err(|e| PdsError::Http(e.to_string()))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsError::DidResolution(format!("HTTP error: {e}")))?;

        if !response.status().is_success() {
            return Err(PdsError::DidResolution(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        response
            .json()
            .await
            .map_err(|e| PdsError::DidResolution(format!("invalid DID document: {e}")))
    }

    async fn resolve_plc(&self, did: &str) -> Result<DidDocument> {
        let url = format!("https://plc.directory/{did}");

        let client = reqwest::Client::builder()
            .timeout(self.http_timeout)
            .build()
            .map_err(|e| PdsError::Http(e.to_string()))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsError::DidResolution(format!("HTTP error: {e}")))?;

        if !response.status().is_success() {
            return Err(PdsError::DidResolution(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        response
            .json()
            .await
            .map_err(|e| PdsError::DidResolution(format!("invalid DID document: {e}")))
    }

    /// Clears the cache.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_did_document() {
        let doc = create_did_document(
            "did:web:example.com",
            "user.example.com",
            "https://pds.example.com",
            "zQ3shtest",
        );

        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.also_known_as, vec!["at://user.example.com"]);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.service.len(), 1);
        assert_eq!(
            doc.service[0].service_type,
            "AtprotoPersonalDataServer"
        );
    }

    #[test]
    fn test_did_resolver_creation() {
        let resolver = DidResolver::new();
        assert!(resolver.get_cached("did:plc:test").is_none());
    }
}
