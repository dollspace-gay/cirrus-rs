//! DID PLC (did:plc) creation and management.
//!
//! Implements the did:plc method for the AT Protocol, including:
//! - Genesis operation creation and signing
//! - DID derivation from signed genesis operations
//! - PLC directory client for registration and resolution

use std::collections::BTreeMap;

use cirrus_common::cid::{base64url_encode, sha256};
use cirrus_common::crypto::Keypair;
use serde::{Deserialize, Serialize};

use crate::error::{PdsError, Result};

/// Default PLC directory URL.
pub const PLC_DIRECTORY_URL: &str = "https://plc.directory";

/// Converts a secp256k1 keypair's public key to `did:key` format.
#[must_use]
pub fn keypair_to_did_key(keypair: &Keypair) -> String {
    format!("did:key:{}", keypair.public_key_multibase())
}

/// A service entry in a PLC operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcService {
    /// Service type (e.g., `"AtprotoPersonalDataServer"`).
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URL.
    pub endpoint: String,
}

/// A signed PLC operation ready for submission to the PLC directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcOperation {
    /// Operation type (`"plc_operation"` or `"plc_tombstone"`).
    #[serde(rename = "type")]
    pub op_type: String,
    /// Rotation keys as `did:key` identifiers (ordered by authority, descending).
    #[serde(rename = "rotationKeys")]
    pub rotation_keys: Vec<String>,
    /// Verification methods mapping service IDs to `did:key` identifiers.
    #[serde(rename = "verificationMethods")]
    pub verification_methods: BTreeMap<String, String>,
    /// Also-known-as URIs (e.g., `at://handle`).
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    /// Services mapping service IDs to service entries.
    pub services: BTreeMap<String, PlcService>,
    /// CID of the previous operation (null for genesis).
    pub prev: Option<String>,
    /// Base64url-encoded ECDSA signature.
    pub sig: String,
}

/// Builds and signs a genesis PLC operation.
///
/// Returns the signed operation and the derived `did:plc` identifier.
///
/// # Errors
/// Returns an error if signing or encoding fails.
pub fn create_genesis_operation(
    rotation_key: &Keypair,
    signing_key: &Keypair,
    handle: &str,
    pds_endpoint: &str,
) -> Result<(PlcOperation, String)> {
    let rotation_did_key = keypair_to_did_key(rotation_key);
    let signing_did_key = keypair_to_did_key(signing_key);

    let mut verification_methods = BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_did_key);

    let mut services = BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: pds_endpoint.to_string(),
        },
    );

    let also_known_as = vec![format!("at://{handle}")];
    let rotation_keys = vec![rotation_did_key];

    // Encode unsigned operation as DAG-CBOR for signing
    let unsigned_cbor = encode_operation_cbor(
        "plc_operation",
        &rotation_keys,
        &verification_methods,
        &also_known_as,
        &services,
        None, // genesis has null prev
        None, // no sig yet
    )?;

    // Sign the unsigned CBOR bytes with the rotation key
    let sig_bytes = rotation_key
        .sign(&unsigned_cbor)
        .map_err(|e| PdsError::Validation(format!("failed to sign PLC operation: {e}")))?;

    let sig = base64url_encode(&sig_bytes);

    // Encode signed operation as DAG-CBOR for DID derivation
    let signed_cbor = encode_operation_cbor(
        "plc_operation",
        &rotation_keys,
        &verification_methods,
        &also_known_as,
        &services,
        None,
        Some(&sig_bytes),
    )?;

    // Derive DID from the signed genesis operation
    let did = derive_did(&signed_cbor);

    let op = PlcOperation {
        op_type: "plc_operation".to_string(),
        rotation_keys,
        verification_methods,
        also_known_as,
        services,
        prev: None,
        sig,
    };

    Ok((op, did))
}

/// Encodes a PLC operation as DAG-CBOR with deterministic key ordering.
///
/// DAG-CBOR requires map keys sorted by encoded byte length, then lexicographically.
/// If `sig` is `None`, produces the unsigned encoding (for signing).
/// If `sig` is `Some`, produces the signed encoding (for DID derivation).
fn encode_operation_cbor(
    op_type: &str,
    rotation_keys: &[String],
    verification_methods: &BTreeMap<String, String>,
    also_known_as: &[String],
    services: &BTreeMap<String, PlcService>,
    prev: Option<&str>,
    sig: Option<&[u8]>,
) -> Result<Vec<u8>> {
    use ciborium::Value as CborValue;

    // Build services map (entries sorted by key length then lex)
    let mut svc_keys: Vec<&String> = services.keys().collect();
    svc_keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    let svc_entries: Vec<(CborValue, CborValue)> = svc_keys
        .iter()
        .map(|key| {
            let svc = &services[*key];
            // Inner map: "type" (4) before "endpoint" (8) by length ordering
            let inner = CborValue::Map(vec![
                (
                    CborValue::Text("type".to_string()),
                    CborValue::Text(svc.service_type.clone()),
                ),
                (
                    CborValue::Text("endpoint".to_string()),
                    CborValue::Text(svc.endpoint.clone()),
                ),
            ]);
            (CborValue::Text((*key).clone()), inner)
        })
        .collect();

    // Build verificationMethods map (sorted by key length then lex)
    let mut vm_keys: Vec<&String> = verification_methods.keys().collect();
    vm_keys.sort_by(|a, b| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));

    let vm_entries: Vec<(CborValue, CborValue)> = vm_keys
        .iter()
        .map(|key| {
            (
                CborValue::Text((*key).clone()),
                CborValue::Text(verification_methods[*key].clone()),
            )
        })
        .collect();

    // Build arrays
    let rk = CborValue::Array(
        rotation_keys
            .iter()
            .map(|k| CborValue::Text(k.clone()))
            .collect(),
    );
    let aka = CborValue::Array(
        also_known_as
            .iter()
            .map(|a| CborValue::Text(a.clone()))
            .collect(),
    );

    let prev_cbor = match prev {
        Some(p) => CborValue::Text(p.to_string()),
        None => CborValue::Null,
    };

    // Build main map with keys sorted by byte length then lexicographically:
    // "sig" (3) < "prev" (4) < "type" (4) < "services" (8) <
    // "alsoKnownAs" (11) < "rotationKeys" (12) < "verificationMethods" (19)
    let mut entries: Vec<(CborValue, CborValue)> = Vec::new();

    if let Some(sig_bytes) = sig {
        entries.push((
            CborValue::Text("sig".to_string()),
            CborValue::Bytes(sig_bytes.to_vec()),
        ));
    }

    entries.push((CborValue::Text("prev".to_string()), prev_cbor));
    entries.push((
        CborValue::Text("type".to_string()),
        CborValue::Text(op_type.to_string()),
    ));
    entries.push((
        CborValue::Text("services".to_string()),
        CborValue::Map(svc_entries),
    ));
    entries.push((CborValue::Text("alsoKnownAs".to_string()), aka));
    entries.push((CborValue::Text("rotationKeys".to_string()), rk));
    entries.push((
        CborValue::Text("verificationMethods".to_string()),
        CborValue::Map(vm_entries),
    ));

    let map = CborValue::Map(entries);

    let mut bytes = Vec::new();
    ciborium::into_writer(&map, &mut bytes)
        .map_err(|e| PdsError::Validation(format!("DAG-CBOR encoding failed: {e}")))?;

    Ok(bytes)
}

/// Derives a `did:plc` identifier from the DAG-CBOR encoding of a signed genesis operation.
///
/// The DID is computed by SHA-256 hashing the signed operation bytes,
/// truncating to 15 bytes (120 bits), and base32-lower encoding to produce
/// a 24-character identifier.
#[must_use]
pub fn derive_did(signed_cbor: &[u8]) -> String {
    let hash = sha256(signed_cbor);
    // Take first 15 bytes (120 bits) → base32-lower → exactly 24 chars
    let truncated = &hash[..15];
    let encoded = multibase::encode(multibase::Base::Base32Lower, truncated);
    // Strip the multibase prefix character ('b' for base32lower)
    let base32_str = &encoded[1..];
    format!("did:plc:{base32_str}")
}

/// PLC directory client for registering and resolving DIDs.
pub struct PlcClient {
    plc_url: String,
    client: reqwest::Client,
}

impl PlcClient {
    /// Creates a new PLC directory client.
    ///
    /// Uses the default PLC directory URL if none is provided.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(plc_url: Option<&str>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| PdsError::Http(format!("failed to create HTTP client: {e}")))?;

        Ok(Self {
            plc_url: plc_url.unwrap_or(PLC_DIRECTORY_URL).to_string(),
            client,
        })
    }

    /// Returns the configured PLC directory URL.
    #[must_use]
    pub fn plc_url(&self) -> &str {
        &self.plc_url
    }

    /// Submits a signed PLC operation to the directory.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the directory rejects the operation.
    pub async fn submit_operation(&self, did: &str, operation: &PlcOperation) -> Result<()> {
        let url = format!("{}/{did}", self.plc_url);

        let response = self
            .client
            .post(&url)
            .json(operation)
            .send()
            .await
            .map_err(|e| PdsError::Http(format!("PLC directory request failed: {e}")))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(PdsError::DidResolution(format!(
                "PLC directory returned {status}: {body}"
            )));
        }

        Ok(())
    }

    /// Creates a new `did:plc` and registers it with the PLC directory.
    ///
    /// Generates a genesis operation, signs it, derives the DID, and submits
    /// the operation to the configured PLC directory.
    ///
    /// # Errors
    /// Returns an error if operation creation or submission fails.
    pub async fn create_did(
        &self,
        rotation_key: &Keypair,
        signing_key: &Keypair,
        handle: &str,
        pds_endpoint: &str,
    ) -> Result<String> {
        let (op, did) = create_genesis_operation(rotation_key, signing_key, handle, pds_endpoint)?;
        self.submit_operation(&did, &op).await?;
        Ok(did)
    }

    /// Resolves a `did:plc` to its DID document from the PLC directory.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails or the response is invalid.
    pub async fn resolve(&self, did: &str) -> Result<crate::did::DidDocument> {
        let url = format!("{}/{did}", self.plc_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsError::Http(format!("PLC directory request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(PdsError::DidResolution(format!(
                "PLC directory returned {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| PdsError::DidResolution(format!("invalid DID document: {e}")))
    }

    /// Fetches the operation log (audit trail) for a `did:plc`.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails.
    pub async fn get_audit_log(&self, did: &str) -> Result<Vec<serde_json::Value>> {
        let url = format!("{}/{did}/log/audit", self.plc_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| PdsError::Http(format!("PLC directory request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(PdsError::DidResolution(format!(
                "PLC audit log returned {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| PdsError::DidResolution(format!("invalid audit log: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_to_did_key() {
        let keypair = Keypair::generate();
        let did_key = keypair_to_did_key(&keypair);

        assert!(did_key.starts_with("did:key:z"));
        // secp256k1 did:key should be ~50 chars
        assert!(did_key.len() > 40);
    }

    #[test]
    fn test_derive_did_format() {
        // Test that derive_did produces correct format
        let test_data = b"test genesis operation data";
        let did = derive_did(test_data);

        assert!(did.starts_with("did:plc:"));
        // did:plc: (8 chars) + 24 base32 chars = 32 total
        assert_eq!(did.len(), 32);

        // Verify all chars in identifier are valid base32 (a-z, 2-7)
        let identifier = &did[8..];
        assert!(identifier
            .chars()
            .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
    }

    #[test]
    fn test_derive_did_deterministic() {
        let data = b"deterministic test data";
        let did1 = derive_did(data);
        let did2 = derive_did(data);
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_derive_did_different_inputs() {
        let did1 = derive_did(b"input one");
        let did2 = derive_did(b"input two");
        assert_ne!(did1, did2);
    }

    #[test]
    fn test_create_genesis_operation() {
        let rotation_key = Keypair::generate();
        let signing_key = Keypair::generate();

        let (op, did) = create_genesis_operation(
            &rotation_key,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("genesis operation should succeed");

        // Check operation structure
        assert_eq!(op.op_type, "plc_operation");
        assert!(op.prev.is_none());
        assert!(!op.sig.is_empty());
        assert_eq!(op.also_known_as, vec!["at://test.example.com"]);
        assert_eq!(op.rotation_keys.len(), 1);
        assert!(op.rotation_keys[0].starts_with("did:key:z"));
        assert!(op.verification_methods.contains_key("atproto"));
        assert!(op.services.contains_key("atproto_pds"));
        assert_eq!(
            op.services["atproto_pds"].service_type,
            "AtprotoPersonalDataServer"
        );
        assert_eq!(
            op.services["atproto_pds"].endpoint,
            "https://pds.example.com"
        );

        // Check DID format
        assert!(did.starts_with("did:plc:"));
        assert_eq!(did.len(), 32);
    }

    #[test]
    fn test_genesis_operation_deterministic() {
        let rotation_key = Keypair::generate();
        let signing_key = Keypair::generate();

        let (_, did1) = create_genesis_operation(
            &rotation_key,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("should succeed");

        let (_, did2) = create_genesis_operation(
            &rotation_key,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("should succeed");

        // Same keys + same metadata = same DID
        assert_eq!(did1, did2);
    }

    #[test]
    fn test_genesis_different_keys_different_did() {
        let rotation_key1 = Keypair::generate();
        let rotation_key2 = Keypair::generate();
        let signing_key = Keypair::generate();

        let (_, did1) = create_genesis_operation(
            &rotation_key1,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("should succeed");

        let (_, did2) = create_genesis_operation(
            &rotation_key2,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("should succeed");

        assert_ne!(did1, did2);
    }

    #[test]
    fn test_genesis_signature_verifiable() {
        let rotation_key = Keypair::generate();
        let signing_key = Keypair::generate();

        let (op, _) = create_genesis_operation(
            &rotation_key,
            &signing_key,
            "test.example.com",
            "https://pds.example.com",
        )
        .expect("should succeed");

        // Decode the signature
        let sig_bytes =
            cirrus_common::cid::base64url_decode(&op.sig).expect("sig should be valid base64url");

        // Re-encode the unsigned operation
        let unsigned_cbor = encode_operation_cbor(
            &op.op_type,
            &op.rotation_keys,
            &op.verification_methods,
            &op.also_known_as,
            &op.services,
            None,
            None,
        )
        .expect("encoding should succeed");

        // Verify signature with the rotation key
        rotation_key
            .public_key()
            .verify(&unsigned_cbor, &sig_bytes)
            .expect("signature should be valid");
    }

    #[test]
    fn test_plc_operation_json_serialization() {
        let rotation_key = Keypair::generate();
        let signing_key = Keypair::generate();

        let (op, _) = create_genesis_operation(
            &rotation_key,
            &signing_key,
            "user.bsky.social",
            "https://pds.bsky.social",
        )
        .expect("should succeed");

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&op).expect("should serialize");

        // Verify JSON structure
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");
        assert_eq!(parsed["type"], "plc_operation");
        assert!(parsed["prev"].is_null());
        assert!(parsed["sig"].is_string());
        assert!(parsed["rotationKeys"].is_array());
        assert!(parsed["verificationMethods"].is_object());
        assert!(parsed["alsoKnownAs"].is_array());
        assert!(parsed["services"].is_object());
    }

    #[test]
    fn test_plc_client_creation() {
        let client = PlcClient::new(None).expect("default client should work");
        assert_eq!(client.plc_url(), PLC_DIRECTORY_URL);

        let custom =
            PlcClient::new(Some("https://plc.custom.com")).expect("custom client should work");
        assert_eq!(custom.plc_url(), "https://plc.custom.com");
    }

    #[test]
    fn test_encode_operation_cbor_deterministic() {
        let mut vm = BTreeMap::new();
        vm.insert("atproto".to_string(), "did:key:zTest123".to_string());

        let mut svcs = BTreeMap::new();
        svcs.insert(
            "atproto_pds".to_string(),
            PlcService {
                service_type: "AtprotoPersonalDataServer".to_string(),
                endpoint: "https://pds.example.com".to_string(),
            },
        );

        let rk = vec!["did:key:zRotation123".to_string()];
        let aka = vec!["at://test.example.com".to_string()];

        let bytes1 = encode_operation_cbor("plc_operation", &rk, &vm, &aka, &svcs, None, None)
            .expect("should encode");
        let bytes2 = encode_operation_cbor("plc_operation", &rk, &vm, &aka, &svcs, None, None)
            .expect("should encode");

        assert_eq!(bytes1, bytes2);
    }
}
