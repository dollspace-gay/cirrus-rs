//! Handle resolution via DNS TXT and HTTP.
//!
//! AT Protocol handles can be resolved to DIDs via two methods:
//! 1. DNS TXT record at `_atproto.{handle}` containing `did=did:plc:xxx`
//! 2. HTTP request to `https://{handle}/.well-known/atproto-did`

use std::collections::HashMap;
use std::time::{Duration, Instant};

use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use parking_lot::RwLock;

use crate::error::{PdsError, Result};

/// Handle resolver with DNS and HTTP support.
pub struct HandleResolver {
    dns_resolver: TokioAsyncResolver,
    cache: RwLock<HashMap<String, CachedHandle>>,
    cache_ttl: Duration,
    http_timeout: Duration,
}

struct CachedHandle {
    did: String,
    cached_at: Instant,
}

/// The result of a handle resolution.
#[derive(Debug, Clone)]
pub struct HandleResolution {
    /// The handle that was resolved.
    pub handle: String,
    /// The DID the handle resolves to.
    pub did: String,
    /// The method used to resolve the handle.
    pub method: ResolutionMethod,
}

/// The method used to resolve a handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMethod {
    /// Resolved via DNS TXT record.
    Dns,
    /// Resolved via HTTP .well-known endpoint.
    Http,
    /// Retrieved from cache.
    Cache,
}

impl Default for HandleResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HandleResolver {
    /// Creates a new handle resolver with default settings.
    ///
    /// # Panics
    /// Panics if the DNS resolver cannot be created.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new() -> Self {
        let dns_resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Self {
            dns_resolver,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300), // 5 minutes
            http_timeout: Duration::from_secs(3),
        }
    }

    /// Creates a resolver with custom settings.
    ///
    /// # Panics
    /// Panics if the DNS resolver cannot be created.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn with_config(cache_ttl: Duration, http_timeout: Duration) -> Self {
        let dns_resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Self {
            dns_resolver,
            cache: RwLock::new(HashMap::new()),
            cache_ttl,
            http_timeout,
        }
    }

    /// Resolves a handle to a DID.
    ///
    /// First checks the cache, then tries DNS TXT, then falls back to HTTP.
    ///
    /// # Errors
    /// Returns an error if resolution fails via all methods.
    pub async fn resolve(&self, handle: &str) -> Result<HandleResolution> {
        // Normalize handle
        let handle = handle.to_lowercase().trim().to_string();

        // Validate handle format to prevent SSRF
        if !is_safe_handle(&handle) {
            return Err(PdsError::HandleResolution(format!(
                "invalid handle format: '{handle}'"
            )));
        }

        // Check cache first
        if let Some(did) = self.get_cached(&handle) {
            return Ok(HandleResolution {
                handle,
                did,
                method: ResolutionMethod::Cache,
            });
        }

        // Try DNS TXT first (preferred method)
        match self.resolve_dns(&handle).await {
            Ok(did) => {
                self.cache_result(&handle, &did);
                return Ok(HandleResolution {
                    handle,
                    did,
                    method: ResolutionMethod::Dns,
                });
            }
            Err(e) => {
                tracing::debug!(handle = %handle, error = %e, "DNS resolution failed, trying HTTP");
            }
        }

        // Fall back to HTTP
        match self.resolve_http(&handle).await {
            Ok(did) => {
                self.cache_result(&handle, &did);
                Ok(HandleResolution {
                    handle,
                    did,
                    method: ResolutionMethod::Http,
                })
            }
            Err(e) => Err(PdsError::HandleResolution(format!(
                "failed to resolve handle '{}': {}",
                handle, e
            ))),
        }
    }

    /// Resolves a handle via DNS TXT record.
    ///
    /// Looks up the TXT record at `_atproto.{handle}`.
    ///
    /// # Errors
    /// Returns an error if DNS lookup fails or no valid DID is found.
    pub async fn resolve_dns(&self, handle: &str) -> Result<String> {
        let query_name = format!("_atproto.{handle}");

        let response = self
            .dns_resolver
            .txt_lookup(&query_name)
            .await
            .map_err(|e| PdsError::HandleResolution(format!("DNS lookup failed: {e}")))?;

        // Look for a TXT record with did=...
        for record in response.iter() {
            for txt in record.iter() {
                let txt_str = String::from_utf8_lossy(txt);
                if let Some(did) = txt_str.strip_prefix("did=") {
                    let did = did.trim();
                    // Validate DID format
                    if did.starts_with("did:plc:") || did.starts_with("did:web:") {
                        return Ok(did.to_string());
                    }
                }
            }
        }

        Err(PdsError::HandleResolution(
            "no valid atproto DID found in DNS TXT records".into(),
        ))
    }

    /// Resolves a handle via HTTP .well-known endpoint.
    ///
    /// Fetches `https://{handle}/.well-known/atproto-did`.
    ///
    /// # Errors
    /// Returns an error if HTTP request fails or response is invalid.
    pub async fn resolve_http(&self, handle: &str) -> Result<String> {
        let url = format!("https://{handle}/.well-known/atproto-did");

        let client = reqwest::Client::builder()
            .timeout(self.http_timeout)
            .build()
            .map_err(|e| PdsError::Http(e.to_string()))?;

        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsError::HandleResolution(format!("HTTP error: {e}")))?;

        if !response.status().is_success() {
            return Err(PdsError::HandleResolution(format!(
                "HTTP {}: {}",
                response.status(),
                url
            )));
        }

        let did = response
            .text()
            .await
            .map_err(|e| PdsError::HandleResolution(format!("failed to read response: {e}")))?
            .trim()
            .to_string();

        // Validate DID format
        if !did.starts_with("did:plc:") && !did.starts_with("did:web:") {
            return Err(PdsError::HandleResolution(format!(
                "invalid DID format: {did}"
            )));
        }

        Ok(did)
    }

    /// Verifies that a handle resolves to the expected DID.
    ///
    /// # Errors
    /// Returns an error if resolution fails or DIDs don't match.
    pub async fn verify(&self, handle: &str, expected_did: &str) -> Result<bool> {
        let resolution = self.resolve(handle).await?;
        Ok(resolution.did == expected_did)
    }

    fn get_cached(&self, handle: &str) -> Option<String> {
        let cache = self.cache.read();
        cache.get(handle).and_then(|cached| {
            if cached.cached_at.elapsed() < self.cache_ttl {
                Some(cached.did.clone())
            } else {
                None
            }
        })
    }

    fn cache_result(&self, handle: &str, did: &str) {
        let mut cache = self.cache.write();
        cache.insert(
            handle.to_string(),
            CachedHandle {
                did: did.to_string(),
                cached_at: Instant::now(),
            },
        );
    }

    /// Clears the cache.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Invalidates a specific handle from the cache.
    pub fn invalidate(&self, handle: &str) {
        self.cache.write().remove(handle);
    }
}

/// Validates a handle is safe for DNS/HTTP resolution (SSRF prevention).
///
/// Rejects handles that could resolve to internal/private IPs:
/// - IP addresses (v4 and v6)
/// - Hex-encoded IPs (0x7f000001)
/// - localhost, internal, local TLDs
/// - Handles shorter than 4 chars or without a dot
fn is_safe_handle(handle: &str) -> bool {
    // Must be reasonable length (at least "a.b" pattern)
    if handle.len() < 4 || handle.len() > 253 {
        return false;
    }

    // Must contain at least one dot (domain-like)
    if !handle.contains('.') {
        return false;
    }

    // Must only contain valid hostname chars
    if !handle
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b))
    {
        return false;
    }

    // Block IP addresses
    if handle.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    if handle.parse::<std::net::Ipv6Addr>().is_ok() {
        return false;
    }

    // Block hex-encoded IPs (e.g., 0x7f000001)
    if handle.starts_with("0x") || handle.starts_with("0X") {
        return false;
    }

    // Block dangerous TLDs and hostnames
    let blocked_patterns = [
        "localhost",
        ".local",
        ".internal",
        ".localhost",
        ".arpa",
        ".onion",
    ];
    for pattern in &blocked_patterns {
        if handle == pattern.trim_start_matches('.') || handle.ends_with(pattern) {
            return false;
        }
    }

    // Block if any segment is purely numeric (could be IP-like)
    let segments: Vec<&str> = handle.split('.').collect();
    if segments.iter().all(|s| s.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_resolver_creation() {
        let resolver = HandleResolver::new();
        assert!(resolver.get_cached("test.handle").is_none());
    }

    #[test]
    fn test_cache_operations() {
        let resolver = HandleResolver::new();

        // Initially not cached
        assert!(resolver.get_cached("test.handle").is_none());

        // Cache a result
        resolver.cache_result("test.handle", "did:plc:test123");

        // Now cached
        assert_eq!(
            resolver.get_cached("test.handle"),
            Some("did:plc:test123".to_string())
        );

        // Invalidate
        resolver.invalidate("test.handle");
        assert!(resolver.get_cached("test.handle").is_none());
    }

    #[test]
    fn test_clear_cache() {
        let resolver = HandleResolver::new();

        resolver.cache_result("handle1", "did:plc:1");
        resolver.cache_result("handle2", "did:plc:2");

        resolver.clear_cache();

        assert!(resolver.get_cached("handle1").is_none());
        assert!(resolver.get_cached("handle2").is_none());
    }

    #[tokio::test]
    async fn test_resolve_returns_cached() {
        let resolver = HandleResolver::new();

        // Pre-cache a result
        resolver.cache_result("cached.handle", "did:plc:cached");

        // Resolve should return cached value
        let result = resolver.resolve("cached.handle").await;
        assert!(result.is_ok());

        let resolution = result.expect("resolution failed");
        assert_eq!(resolution.did, "did:plc:cached");
        assert_eq!(resolution.method, ResolutionMethod::Cache);
    }

    #[test]
    fn test_safe_handle_valid() {
        assert!(is_safe_handle("bsky.app"));
        assert!(is_safe_handle("alice.bsky.social"));
        assert!(is_safe_handle("my-handle.example.com"));
        assert!(is_safe_handle("hyperintellectual-uncommercial-dudley.ngrok-free.dev"));
    }

    #[test]
    fn test_safe_handle_blocks_ip() {
        assert!(!is_safe_handle("127.0.0.1"));
        assert!(!is_safe_handle("192.168.1.1"));
        assert!(!is_safe_handle("169.254.169.254"));
        assert!(!is_safe_handle("0x7f000001"));
    }

    #[test]
    fn test_safe_handle_blocks_internal() {
        assert!(!is_safe_handle("localhost"));
        assert!(!is_safe_handle("app.localhost"));
        assert!(!is_safe_handle("test.local"));
        assert!(!is_safe_handle("host.internal"));
    }

    #[test]
    fn test_safe_handle_blocks_short() {
        assert!(!is_safe_handle("a"));
        assert!(!is_safe_handle("ab"));
        assert!(!is_safe_handle("abc"));
    }

    #[tokio::test]
    async fn test_resolve_blocks_ssrf() {
        let resolver = HandleResolver::new();
        assert!(resolver.resolve("127.0.0.1").await.is_err());
        assert!(resolver.resolve("localhost").await.is_err());
        assert!(resolver.resolve("169.254.169.254").await.is_err());
        assert!(resolver.resolve("0x7f000001").await.is_err());
        assert!(resolver.resolve("evil.localhost").await.is_err());
    }
}
