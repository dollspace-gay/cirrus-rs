//! Crawler/relay notification for AT Protocol federation.
//!
//! After every commit, the PDS notifies configured relay URLs via
//! `com.atproto.sync.requestCrawl`. Notifications are rate-limited to
//! at most one per 20 minutes to avoid flooding relays.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::warn;

/// Minimum interval between crawler notifications (20 minutes).
const NOTIFY_THRESHOLD: Duration = Duration::from_secs(20 * 60);

/// Manages outbound crawler/relay notifications.
#[derive(Clone)]
pub struct Crawlers {
    inner: Arc<CrawlersInner>,
}

struct CrawlersInner {
    /// This PDS's hostname sent in requestCrawl.
    hostname: String,
    /// Configured relay/crawler service URLs.
    relay_urls: Vec<String>,
    /// HTTP client for making requests.
    client: reqwest::Client,
    /// Timestamp of last successful notification.
    last_notified: Mutex<Option<Instant>>,
}

impl Crawlers {
    /// Creates a new `Crawlers` instance.
    ///
    /// `hostname` is this PDS's hostname (e.g. `my-pds.example.com`).
    /// `relay_urls` are the base URLs of relays to notify (e.g. `https://bsky.network`).
    #[must_use]
    pub fn new(hostname: String, relay_urls: Vec<String>) -> Self {
        Self {
            inner: Arc::new(CrawlersInner {
                hostname,
                relay_urls,
                client: reqwest::Client::new(),
                last_notified: Mutex::new(None),
            }),
        }
    }

    /// Returns whether any relay URLs are configured.
    #[must_use]
    pub fn has_relays(&self) -> bool {
        !self.inner.relay_urls.is_empty()
    }

    /// Notifies configured relays of a new update, if the rate limit allows.
    ///
    /// This method is non-blocking: it spawns background tasks for each relay.
    /// If called within the rate limit window, it silently returns without
    /// notifying.
    pub async fn notify_of_update(&self) {
        self.send_request_crawl(false).await;
    }

    /// Notifies configured relays immediately, bypassing the rate limit.
    ///
    /// Use this for critical one-time events like account tombstones that
    /// must reach relays regardless of recent notification history.
    pub async fn notify_immediate(&self) {
        self.send_request_crawl(true).await;
    }

    async fn send_request_crawl(&self, bypass_rate_limit: bool) {
        if self.inner.relay_urls.is_empty() {
            return;
        }

        // Check rate limit (skipped for immediate notifications)
        {
            let mut last = self.inner.last_notified.lock().await;
            let now = Instant::now();
            if !bypass_rate_limit {
                if let Some(prev) = *last {
                    if now.duration_since(prev) < NOTIFY_THRESHOLD {
                        return;
                    }
                }
            }
            *last = Some(now);
        }

        // Spawn background tasks for each relay
        for url in &self.inner.relay_urls {
            let inner = Arc::clone(&self.inner);
            let relay_url = url.clone();
            tokio::spawn(async move {
                let endpoint = format!(
                    "{}/xrpc/com.atproto.sync.requestCrawl",
                    relay_url.trim_end_matches('/')
                );
                let body = serde_json::json!({
                    "hostname": inner.hostname
                });

                match inner.client.post(&endpoint).json(&body).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::info!(relay = %relay_url, "requestCrawl accepted");
                    }
                    Ok(resp) => {
                        warn!(
                            relay = %relay_url,
                            status = %resp.status(),
                            "requestCrawl returned non-success status"
                        );
                    }
                    Err(err) => {
                        warn!(
                            relay = %relay_url,
                            error = %err,
                            "failed to send requestCrawl"
                        );
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawlers_creation() {
        let crawlers = Crawlers::new(
            "my-pds.example.com".to_string(),
            vec!["https://bsky.network".to_string()],
        );
        assert!(crawlers.has_relays());
    }

    #[test]
    fn test_crawlers_no_relays() {
        let crawlers = Crawlers::new("my-pds.example.com".to_string(), vec![]);
        assert!(!crawlers.has_relays());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        // Create crawlers with a non-existent relay (won't actually connect)
        let crawlers = Crawlers::new(
            "test.example.com".to_string(),
            vec!["http://127.0.0.1:1".to_string()],
        );

        // First call should pass rate limit (updates last_notified)
        crawlers.notify_of_update().await;
        let last = *crawlers.inner.last_notified.lock().await;
        assert!(last.is_some());

        // Second call within threshold should be rate-limited (last_notified unchanged)
        let first_time = last.unwrap();
        crawlers.notify_of_update().await;
        let after_second = *crawlers.inner.last_notified.lock().await;
        assert_eq!(first_time, after_second.unwrap());
    }

    #[tokio::test]
    async fn test_no_relays_noop() {
        let crawlers = Crawlers::new("test.example.com".to_string(), vec![]);
        // Should return immediately without updating last_notified
        crawlers.notify_of_update().await;
        let last = *crawlers.inner.last_notified.lock().await;
        assert!(last.is_none());
    }
}
