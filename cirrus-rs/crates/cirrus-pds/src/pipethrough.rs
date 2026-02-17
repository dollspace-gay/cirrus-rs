//! Appview pipethrough for proxying read requests.
//!
//! Bluesky clients send all read requests (getProfile, getTimeline, etc.) to the
//! PDS, which proxies them to an AppView service using service auth JWTs. Without
//! this, clients cannot use Cirrus as their API endpoint for reads.

use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use tracing::warn;

/// Configuration for the appview proxy.
#[derive(Clone, Debug)]
pub struct AppViewConfig {
    /// Base URL of the appview service (e.g. `https://api.bsky.app`).
    pub url: String,
    /// DID of the appview service (e.g. `did:web:api.bsky.app`).
    pub did: String,
}

/// Proxies a request to the configured appview.
///
/// Creates a service auth JWT signed with the repo signing key and forwards the
/// request (method, path, query, relevant headers) to the appview. Returns the
/// appview's response directly to the client.
pub async fn proxy_request(
    config: &AppViewConfig,
    signing_key: &cirrus_common::crypto::Keypair,
    issuer_did: &str,
    method: &Method,
    original_uri: &str,
    request_headers: &HeaderMap,
    body: Option<bytes::Bytes>,
) -> Response {
    // Extract the NSID from the URI path for lxm claim
    let lxm = original_uri
        .strip_prefix("/xrpc/")
        .and_then(|rest| rest.split('?').next())
        .unwrap_or("");

    // Create service auth JWT
    let token = match create_service_jwt(signing_key, issuer_did, &config.did, lxm) {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "failed to create service JWT for pipethrough");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create service auth",
            )
                .into_response();
        }
    };

    // Build upstream URL
    let upstream_url = format!("{}{}", config.url.trim_end_matches('/'), original_uri);

    // Build upstream request
    let client = reqwest::Client::new();
    let mut upstream = match *method {
        Method::GET => client.get(&upstream_url),
        Method::HEAD => client.head(&upstream_url),
        Method::POST => client.post(&upstream_url),
        _ => {
            return (
                StatusCode::METHOD_NOT_ALLOWED,
                "Only GET, HEAD, POST supported",
            )
                .into_response();
        }
    };

    // Set auth header
    upstream = upstream.header("authorization", format!("Bearer {token}"));

    // Forward relevant headers
    for (name, value) in request_headers {
        let name_str = name.as_str();
        match name_str {
            "accept-language" | "atproto-accept-labelers" | "x-bsky-topics" => {
                upstream = upstream.header(name_str, value);
            }
            "content-type" | "content-encoding" if body.is_some() => {
                upstream = upstream.header(name_str, value);
            }
            "accept-encoding" => {
                upstream = upstream.header(name_str, value);
            }
            _ => {}
        }
    }

    // Forward body if present
    if let Some(body_bytes) = body {
        upstream = upstream.body(body_bytes);
    }

    // Execute request
    let upstream_resp = match upstream.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, url = %upstream_url, "pipethrough request failed");
            return (StatusCode::BAD_GATEWAY, "Upstream request failed").into_response();
        }
    };

    // Build response
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut response_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers() {
        let name_str = name.as_str();
        match name_str {
            "content-type"
            | "content-encoding"
            | "content-language"
            | "atproto-content-labelers"
            | "atproto-repo-rev" => {
                if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
                    response_headers.insert(name.clone(), v);
                }
            }
            _ => {}
        }
    }

    let body_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to read upstream response body");
            return (StatusCode::BAD_GATEWAY, "Failed to read upstream response").into_response();
        }
    };

    (status, response_headers, body_bytes).into_response()
}

/// Returns true if the given NSID should be proxied to the appview.
///
/// Proxies `app.bsky.*` and `app.bsky.unspecced.*` namespaces, plus
/// `chat.bsky.*` reads, which are handled by the appview.
#[must_use]
pub fn should_proxy(nsid: &str) -> bool {
    nsid.starts_with("app.bsky.") || nsid.starts_with("chat.bsky.")
}

/// Creates a service auth JWT for pipethrough requests.
fn create_service_jwt(
    signing_key: &cirrus_common::crypto::Keypair,
    issuer_did: &str,
    audience_did: &str,
    lxm: &str,
) -> Result<String, cirrus_common::error::Error> {
    let claims = cirrus_common::jwt::Claims::new(issuer_did, 60) // 60s expiry
        .with_aud(audience_did)
        .with_lxm(lxm);
    cirrus_common::jwt::sign_es256k(&claims, signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_proxy() {
        assert!(should_proxy("app.bsky.feed.getTimeline"));
        assert!(should_proxy("app.bsky.actor.getProfile"));
        assert!(should_proxy("app.bsky.graph.getFollowers"));
        assert!(should_proxy("app.bsky.unspecced.getPopularFeedGenerators"));
        assert!(should_proxy("chat.bsky.convo.getMessages"));

        assert!(!should_proxy("com.atproto.repo.getRecord"));
        assert!(!should_proxy("com.atproto.server.createSession"));
        assert!(!should_proxy("com.atproto.sync.getRepo"));
    }

    #[test]
    fn test_create_service_jwt() {
        let keypair = cirrus_common::crypto::Keypair::generate();
        let token = create_service_jwt(
            &keypair,
            "did:plc:issuer",
            "did:web:api.bsky.app",
            "app.bsky.feed.getTimeline",
        )
        .unwrap();

        // Verify it's a valid JWT
        assert_eq!(token.split('.').count(), 3);

        // Decode and verify claims
        let claims: cirrus_common::jwt::Claims =
            cirrus_common::jwt::decode_unverified(&token).unwrap();
        assert_eq!(claims.iss, "did:plc:issuer");
        assert_eq!(claims.aud, Some("did:web:api.bsky.app".to_string()));
        assert_eq!(claims.lxm, Some("app.bsky.feed.getTimeline".to_string()));
    }
}
