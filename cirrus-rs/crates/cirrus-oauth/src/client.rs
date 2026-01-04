//! OAuth client resolution from DID documents.

use crate::error::{OAuthError, Result};
use crate::storage::ClientMetadata;

/// Resolves client metadata from a DID.
///
/// # Errors
/// Returns an error if the DID cannot be resolved or has no OAuth metadata.
pub async fn resolve_client(client_id: &str) -> Result<ClientMetadata> {
    // Validate it's a DID
    if !client_id.starts_with("did:") {
        return Err(OAuthError::InvalidClient(
            "client_id must be a DID".into(),
        ));
    }

    // Resolve DID document
    let did_doc = resolve_did_document(client_id).await?;

    // Extract OAuth client metadata from service endpoints
    extract_client_metadata(client_id, &did_doc)
}

async fn resolve_did_document(did: &str) -> Result<serde_json::Value> {
    let url = if did.starts_with("did:web:") {
        // did:web resolution
        let domain = did.strip_prefix("did:web:").unwrap_or("");
        let domain = domain.replace(':', "/");
        format!("https://{domain}/.well-known/did.json")
    } else if did.starts_with("did:plc:") {
        // did:plc resolution
        format!("https://plc.directory/{did}")
    } else {
        return Err(OAuthError::InvalidClient(format!(
            "unsupported DID method: {did}"
        )));
    };

    let response = reqwest::get(&url)
        .await
        .map_err(|e| OAuthError::Http(e.to_string()))?;

    if !response.status().is_success() {
        return Err(OAuthError::InvalidClient(format!(
            "failed to resolve DID: HTTP {}",
            response.status()
        )));
    }

    response
        .json()
        .await
        .map_err(|e| OAuthError::InvalidClient(format!("invalid DID document: {e}")))
}

fn extract_client_metadata(client_id: &str, did_doc: &serde_json::Value) -> Result<ClientMetadata> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Look for AtprotoOAuthClient service
    let services = did_doc["service"].as_array();

    let oauth_service = services
        .and_then(|s| {
            s.iter().find(|svc| {
                svc["type"].as_str() == Some("AtprotoOAuthClient")
            })
        });

    // Extract redirect URIs from service endpoint or alsoKnownAs
    let redirect_uris = if let Some(svc) = oauth_service {
        if let Some(endpoint) = svc["serviceEndpoint"].as_str() {
            vec![endpoint.to_string()]
        } else if let Some(endpoints) = svc["serviceEndpoint"].as_array() {
            endpoints
                .iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        // Fallback: use alsoKnownAs handles as redirect URI base
        Vec::new()
    };

    if redirect_uris.is_empty() {
        return Err(OAuthError::InvalidClient(
            "no redirect URIs found in DID document".into(),
        ));
    }

    Ok(ClientMetadata {
        client_id: client_id.to_string(),
        client_name: None, // Could be extracted from profile
        redirect_uris,
        logo_uri: None,
        client_uri: None,
        cached_at: now,
    })
}

/// Validates that a redirect URI is allowed for a client.
///
/// # Errors
/// Returns an error if the redirect URI is not allowed.
pub fn validate_redirect_uri(metadata: &ClientMetadata, redirect_uri: &str) -> Result<()> {
    if metadata.redirect_uris.contains(&redirect_uri.to_string()) {
        Ok(())
    } else {
        Err(OAuthError::InvalidRequest(format!(
            "redirect_uri not allowed: {redirect_uri}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_redirect_uri() {
        let metadata = ClientMetadata {
            client_id: "did:web:example.com".to_string(),
            client_name: None,
            redirect_uris: vec![
                "https://example.com/callback".to_string(),
                "https://example.com/oauth".to_string(),
            ],
            logo_uri: None,
            client_uri: None,
            cached_at: 0,
        };

        assert!(validate_redirect_uri(&metadata, "https://example.com/callback").is_ok());
        assert!(validate_redirect_uri(&metadata, "https://example.com/oauth").is_ok());
        assert!(validate_redirect_uri(&metadata, "https://evil.com/callback").is_err());
    }
}
