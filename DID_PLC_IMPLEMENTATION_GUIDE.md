# did:plc Implementation Guide - Code Examples

This guide provides practical code examples for implementing did:plc in Rust.

---

## 1. Operation Structure Examples

### 1.1 Genesis Operation (Creation)

```json
{
  "type": "plc_operation",
  "rotationKeys": [
    "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4"
  ],
  "verificationMethods": {
    "atproto": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
  },
  "alsoKnownAs": [
    "at://alice.example.com"
  ],
  "services": {
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"
    }
  },
  "prev": null,
  "sig": "ICjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
}
```

### 1.2 Update Operation (Key Rotation)

```json
{
  "type": "plc_operation",
  "rotationKeys": [
    "did:key:zk3ttaaBzjMupzBVJGgf3BpKvL5LdhYZqYy8G7AXQfHjW5Hh9",
    "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4"
  ],
  "verificationMethods": {
    "atproto": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
  },
  "alsoKnownAs": [
    "at://alice.example.com"
  ],
  "services": {
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"
    }
  },
  "prev": "bafyreigltznq3w3g2btjmqr54vjxib37zw73kmjxpzf2s4zzwwwl5mqcq",
  "sig": "KCjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
}
```

### 1.3 Tombstone Operation (Deactivation)

```json
{
  "type": "plc_tombstone",
  "prev": "bafyreigltznq3w3g2btjmqr54vjxib37zw73kmjxpzf2s4zzwwwl5mqcq",
  "sig": "LCjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
}
```

### 1.4 Legacy Create Operation (Backward Compatibility)

```json
{
  "type": "create",
  "signingKey": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX",
  "recoveryKey": "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4",
  "handle": "alice.example.com",
  "service": "https://pds.example.com",
  "prev": null,
  "sig": "ICjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
}
```

---

## 2. Rust Structures

### 2.1 Operation Enums

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PlcOperation {
    PlcOp(PlcOperationBody),
    Tombstone(TombstoneOperation),
    LegacyCreate(LegacyCreateOperation),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlcOperationBody {
    #[serde(rename = "type")]
    pub op_type: String, // "plc_operation"

    pub rotation_keys: Vec<String>,
    pub verification_methods: HashMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: HashMap<String, Service>,

    pub prev: Option<String>,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneOperation {
    #[serde(rename = "type")]
    pub op_type: String, // "plc_tombstone"

    pub prev: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyCreateOperation {
    #[serde(rename = "type")]
    pub op_type: String, // "create"

    pub signing_key: String,
    pub recovery_key: String,
    pub handle: String,
    pub service: String,
    pub prev: (),
    pub sig: String,
}

/// Unsigned operation for signing (excludes sig field)
#[derive(Debug, Clone, Serialize)]
pub struct UnsignedPlcOperation {
    #[serde(rename = "type")]
    pub op_type: String, // "plc_operation"

    pub rotation_keys: Vec<String>,
    pub verification_methods: HashMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: HashMap<String, Service>,

    pub prev: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PlcDidState {
    pub did: String,
    pub rotation_keys: Vec<String>,
    pub verification_methods: HashMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: HashMap<String, Service>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub cid: String,
    pub operation: serde_json::Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub nullified: bool,
}
```

---

## 3. Key Operations

### 3.1 Generate Keys

```rust
use k256::ecdsa::SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use rand::OsRng;

/// Generate a secp256k1 key pair (recommended for recovery keys)
pub fn generate_k256_key() -> Result<(String, Vec<u8>)> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Convert to did:key format
    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let did_key = encode_to_did_key_k256(&public_key_bytes)?;
    let private_key_bytes = signing_key.to_bytes().to_vec();

    Ok((did_key, private_key_bytes))
}

/// Generate a NIST P-256 key pair
pub fn generate_p256_key() -> Result<(String, Vec<u8>)> {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
    let did_key = encode_to_did_key_p256(&public_key_bytes)?;
    let private_key_bytes = signing_key.to_bytes().to_vec();

    Ok((did_key, private_key_bytes))
}

/// Encode public key to did:key format (k256)
fn encode_to_did_key_k256(public_key_bytes: &[u8]) -> Result<String> {
    // did:key format for secp256k1:
    // did:key:z + base58btc(multicodec_prefix + public_key)
    // multicodec prefix for k256: 0xe7 (varint encoded as 0xe7 0x01)

    let mut prefixed = vec![0xe7, 0x01];
    prefixed.extend_from_slice(public_key_bytes);

    let encoded = bs58::encode(&prefixed).into_string();
    Ok(format!("did:key:z{}", encoded))
}

/// Encode public key to did:key format (p256)
fn encode_to_did_key_p256(public_key_bytes: &[u8]) -> Result<String> {
    // multicodec prefix for p256: 0x80 0x02
    let mut prefixed = vec![0x80, 0x02];
    prefixed.extend_from_slice(public_key_bytes);

    let encoded = bs58::encode(&prefixed).into_string();
    Ok(format!("did:key:z{}", encoded))
}
```

### 3.2 Sign Operation

```rust
use sha2::{Sha256, Digest};
use k256::ecdsa::{SigningKey, signature::Signer};

/// Sign an operation with a rotation key
pub fn sign_operation(
    unsigned_op: &UnsignedPlcOperation,
    private_key_bytes: &[u8],
) -> Result<String> {
    // 1. Encode operation as DAG-CBOR
    let cbor_bytes = operation_to_dagcbor(unsigned_op)?;

    // 2. Sign the bytes with ECDSA-SHA256
    let signing_key = SigningKey::from_slice(private_key_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid private key"))?;

    let signature = signing_key.sign(&cbor_bytes);
    let sig_bytes = signature.to_bytes();

    // 3. Ensure "low-S" canonical form
    let sig_bytes = ensure_low_s(&sig_bytes)?;

    // 4. Encode as base64url (no padding)
    let sig_b64url = base64_simd::URL_SAFE_NO_PAD.encode_to_string(&sig_bytes);

    Ok(sig_b64url)
}

/// Ensure signature is in "low-S" canonical form (BIP-0062)
fn ensure_low_s(sig_bytes: &[u8]) -> Result<Vec<u8>> {
    if sig_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid signature length"));
    }

    // Extract r and s (32 bytes each, big-endian)
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];

    // For secp256k1, the group order is:
    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    // If s > n/2, replace with n - s

    let order_half = hex::decode(
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
    )?;

    let s_int = u256::from_be_bytes(s);
    let half_int = u256::from_be_bytes(&order_half);

    let final_s = if s_int > half_int {
        let order = u256::from_hex_str(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        )?;
        (order - s_int).to_be_bytes()
    } else {
        s.to_vec()
    };

    let mut result = vec![0u8; 64];
    result[0..32].copy_from_slice(r);
    result[32..64].copy_from_slice(&final_s);

    Ok(result)
}
```

### 3.3 DAG-CBOR Encoding

```rust
use ciborium::value::Value as CborValue;
use ciborium::ser::into_writer;
use std::collections::BTreeMap;

/// Convert operation to DAG-CBOR bytes
pub fn operation_to_dagcbor(op: &UnsignedPlcOperation) -> Result<Vec<u8>> {
    // Build a CBOR value matching the operation structure
    let mut map = BTreeMap::new();

    map.insert(
        CborValue::Text("type".into()),
        CborValue::Text(op.op_type.clone()),
    );

    // Encode rotationKeys as array
    let rotation_keys: Vec<CborValue> = op.rotation_keys
        .iter()
        .map(|k| CborValue::Text(k.clone()))
        .collect();
    map.insert(
        CborValue::Text("rotationKeys".into()),
        CborValue::Array(rotation_keys),
    );

    // Encode verificationMethods as map
    let mut verification_map = BTreeMap::new();
    for (key, value) in &op.verification_methods {
        verification_map.insert(
            CborValue::Text(key.clone()),
            CborValue::Text(value.clone()),
        );
    }
    map.insert(
        CborValue::Text("verificationMethods".into()),
        CborValue::Map(verification_map),
    );

    // Encode alsoKnownAs as array
    let also_known_as: Vec<CborValue> = op.also_known_as
        .iter()
        .map(|k| CborValue::Text(k.clone()))
        .collect();
    map.insert(
        CborValue::Text("alsoKnownAs".into()),
        CborValue::Array(also_known_as),
    );

    // Encode services as map
    let mut services_map = BTreeMap::new();
    for (key, service) in &op.services {
        let mut service_obj = BTreeMap::new();
        service_obj.insert(
            CborValue::Text("type".into()),
            CborValue::Text(service.service_type.clone()),
        );
        service_obj.insert(
            CborValue::Text("endpoint".into()),
            CborValue::Text(service.endpoint.clone()),
        );
        services_map.insert(
            CborValue::Text(key.clone()),
            CborValue::Map(service_obj),
        );
    }
    map.insert(
        CborValue::Text("services".into()),
        CborValue::Map(services_map),
    );

    // Encode prev (nullable)
    let prev_value = match &op.prev {
        Some(cid) => CborValue::Text(cid.clone()),
        None => CborValue::Null,
    };
    map.insert(CborValue::Text("prev".into()), prev_value);

    // Serialize to bytes
    let mut bytes = Vec::new();
    into_writer(&CborValue::Map(map), &mut bytes)?;

    Ok(bytes)
}
```

### 3.4 Derive DID

```rust
use sha2::{Sha256, Digest};
use base32::{Alphabet, encode};

/// Derive did:plc identifier from genesis operation
pub fn derive_did(genesis_operation: &PlcOperationBody) -> Result<String> {
    // 1. Encode operation as DAG-CBOR
    let unsigned = UnsignedPlcOperation {
        op_type: genesis_operation.op_type.clone(),
        rotation_keys: genesis_operation.rotation_keys.clone(),
        verification_methods: genesis_operation.verification_methods.clone(),
        also_known_as: genesis_operation.also_known_as.clone(),
        services: genesis_operation.services.clone(),
        prev: None,
    };

    let cbor_bytes = operation_to_dagcbor(&unsigned)?;

    // 2. Hash with SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let hash_bytes = hasher.finalize();

    // 3. Base32 encode (lowercase, no padding)
    let hash_vec = hash_bytes.to_vec();
    let encoded = encode(Alphabet::RFC4648 { padding: false }, &hash_vec);

    // 4. Truncate to 24 characters
    let truncated = &encoded[0..24.min(encoded.len())];

    // 5. Generate DID
    Ok(format!("did:plc:{}", truncated))
}

/// Compute CID for an operation (for use in prev field)
pub fn compute_operation_cid(operation_bytes: &[u8]) -> Result<String> {
    // CIDv1 base32 dag-cbor sha256
    // Format: b (base32) + z (variable-length int) + codec + hash

    let mut hasher = Sha256::new();
    hasher.update(operation_bytes);
    let hash_bytes = hasher.finalize();

    // CIDv1: [1, dag-cbor (0x71), sha256 (0x12), hash_length, hash_bytes]
    let mut cid_bytes = vec![0x01, 0x71, 0x12, 0x20]; // 0x20 = 32 bytes for sha256
    cid_bytes.extend_from_slice(&hash_bytes);

    // Base32 encode with 'b' prefix
    let encoded = encode(Alphabet::RFC4648 { padding: false }, &cid_bytes);
    Ok(format!("b{}", encoded))
}
```

---

## 4. Directory API Interaction

### 4.1 HTTP Client Setup

```rust
use reqwest::Client;
use std::time::Duration;

/// Create an HTTP client for PLC directory interactions
pub fn create_plc_client() -> Result<Client> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("my-pds/1.0.0")
        .build()?;

    Ok(client)
}

#[derive(Debug)]
pub struct PlcDirectory {
    client: Client,
    base_url: String,
}

impl PlcDirectory {
    pub fn new(client: Client, base_url: String) -> Self {
        Self { client, base_url }
    }

    pub fn default() -> Self {
        Self::new(
            create_plc_client().expect("Failed to create client"),
            "https://plc.directory".into(),
        )
    }
}
```

### 4.2 Create/Update DID

```rust
use reqwest::StatusCode;

impl PlcDirectory {
    /// Submit a DID operation to the directory
    pub async fn submit_operation(
        &self,
        did: &str,
        operation: &PlcOperationBody,
    ) -> Result<()> {
        let url = format!("{}/{}", self.base_url, did);

        let response = self.client
            .post(&url)
            .json(operation)
            .send()
            .await?;

        match response.status() {
            StatusCode::OK => Ok(()),
            StatusCode::BAD_REQUEST => {
                let body = response.text().await?;
                Err(anyhow::anyhow!("Bad request: {}", body))
            }
            StatusCode::CONFLICT => {
                let body = response.text().await?;
                Err(anyhow::anyhow!("Conflict (invalid signature?): {}", body))
            }
            other => {
                let body = response.text().await?;
                Err(anyhow::anyhow!("HTTP {}: {}", other, body))
            }
        }
    }
}
```

### 4.3 Resolve DID

```rust
impl PlcDirectory {
    /// Get W3C DID Document from directory
    pub async fn resolve_did_document(&self, did: &str) -> Result<serde_json::Value> {
        let url = format!("{}/{}", self.base_url, did);

        let response = self.client.get(&url).send().await?;

        match response.status() {
            StatusCode::OK => response.json().await.map_err(Into::into),
            StatusCode::NOT_FOUND => {
                Err(anyhow::anyhow!("DID not found: {}", did))
            }
            other => {
                let body = response.text().await?;
                Err(anyhow::anyhow!("HTTP {}: {}", other, body))
            }
        }
    }

    /// Get current DID state data (not DID document format)
    pub async fn resolve_did_state(&self, did: &str) -> Result<PlcDidState> {
        let url = format!("{}/{}/data", self.base_url, did);

        let response = self.client.get(&url).send().await?;
        let json: serde_json::Value = response.json().await?;

        // Parse into PlcDidState structure
        Ok(PlcDidState {
            did: json["did"].as_str().unwrap_or("").into(),
            rotation_keys: json["rotationKeys"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            verification_methods: json["verificationMethods"]
                .as_object()
                .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").into())).collect())
                .unwrap_or_default(),
            also_known_as: json["alsoKnownAs"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            services: json["services"]
                .as_object()
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            if let Some(obj) = v.as_object() {
                                Some((
                                    k.clone(),
                                    Service {
                                        service_type: obj["type"].as_str().unwrap_or("").into(),
                                        endpoint: obj["endpoint"].as_str().unwrap_or("").into(),
                                    },
                                ))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Get audit log for DID
    pub async fn get_audit_log(&self, did: &str) -> Result<Vec<AuditLogEntry>> {
        let url = format!("{}/{}/log/audit", self.base_url, did);

        let response = self.client.get(&url).send().await?;
        let entries: Vec<AuditLogEntry> = response.json().await?;

        Ok(entries)
    }
}
```

---

## 5. Full DID Creation Workflow

```rust
/// Complete workflow for creating a did:plc during account registration
pub async fn create_did_for_account(
    directory: &PlcDirectory,
    handle: &str,
    pds_url: &str,
) -> Result<(String, PlcDidState)> {
    // Step 1: Generate keys
    let (recovery_key, recovery_key_private) = generate_k256_key()?;
    let (signing_key, _signing_key_private) = generate_p256_key()?;

    // Step 2: Build genesis operation
    let mut verification_methods = std::collections::HashMap::new();
    verification_methods.insert("atproto".into(), signing_key.clone());

    let mut services = std::collections::HashMap::new();
    services.insert("atproto_pds".into(), Service {
        service_type: "AtprotoPersonalDataServer".into(),
        endpoint: pds_url.into(),
    });

    let unsigned_op = UnsignedPlcOperation {
        op_type: "plc_operation".into(),
        rotation_keys: vec![recovery_key.clone()],
        verification_methods: verification_methods.clone(),
        also_known_as: vec![format!("at://{}", handle)],
        services: services.clone(),
        prev: None,
    };

    // Step 3: Sign operation
    let sig = sign_operation(&unsigned_op, &recovery_key_private)?;

    // Step 4: Create signed operation
    let signed_op = PlcOperationBody {
        op_type: "plc_operation".into(),
        rotation_keys: unsigned_op.rotation_keys.clone(),
        verification_methods: unsigned_op.verification_methods.clone(),
        also_known_as: unsigned_op.also_known_as.clone(),
        services: unsigned_op.services.clone(),
        prev: None,
        sig,
    };

    // Step 5: Derive DID
    let did = derive_did(&signed_op)?;

    // Step 6: Submit to directory
    directory.submit_operation(&did, &signed_op).await?;

    // Step 7: Verify by resolving
    let state = directory.resolve_did_state(&did).await?;

    Ok((did, state))
}
```

---

## 6. Signature Validation

```rust
use k256::ecdsa::{VerifyingKey, signature::Verifier};

/// Verify operation signature against rotation keys
pub fn verify_operation_signature(
    operation_bytes: &[u8],
    rotation_key_did: &str,
    signature_b64url: &str,
) -> Result<bool> {
    // 1. Decode rotation key from did:key
    let public_key_bytes = decode_did_key(rotation_key_did)?;

    // 2. Decode signature from base64url
    let sig_bytes = base64_simd::URL_SAFE_NO_PAD.decode_to_vec(signature_b64url)?;

    if sig_bytes.len() != 64 {
        return Err(anyhow::anyhow!("Invalid signature length"));
    }

    // 3. Extract r and s components
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];

    // 4. Verify "low-S" canonical form
    if !is_low_s(s)? {
        return Err(anyhow::anyhow!("Signature not in canonical low-S form"));
    }

    // 5. Create verifying key from public key bytes
    let verifying_key = VerifyingKey::from_encoded_point(
        &k256::elliptic_curve::PublicKey::from_bytes(&public_key_bytes)?
            .to_encoded_point(false),
    )?;

    // 6. Verify signature
    let signature = k256::ecdsa::Signature::from_components(r, s);
    verifying_key.verify(operation_bytes, &signature)
        .map(|_| true)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
}

fn is_low_s(s_bytes: &[u8]) -> Result<bool> {
    let order_half = hex::decode(
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
    )?;

    let s_int = u256::from_be_bytes(s_bytes);
    let half_int = u256::from_be_bytes(&order_half);

    Ok(s_int <= half_int)
}
```

---

## 7. Validation Checklist for Implementation

When implementing did:plc support, verify:

- [ ] **Keys**: Support secp256k1 and NIST P-256 for rotation keys
- [ ] **DAG-CBOR**: Use deterministic encoding, exclude sig field for signing
- [ ] **Signatures**: ECDSA-SHA256, base64url encoding, "low-S" canonical form
- [ ] **DID Derivation**: SHA-256 hash, base32 encode, truncate to 24 chars
- [ ] **Operation Limits**: Reject operations > 7500 bytes when DAG-CBOR encoded
- [ ] **Recovery Window**: Enforce 72-hour window for recovery operations
- [ ] **Key Rotation**: Validate rotation key ordering by authority
- [ ] **Error Handling**: Distinguish between validation errors and HTTP errors
- [ ] **did:key Parsing**: Support multibase base58btc decoding
- [ ] **CID Format**: Use CIDv1 base32 dag-cbor sha256 for prev references
- [ ] **Handle Validation**: Verify bi-directionally (DID -> handle -> DID)
- [ ] **Tombstones**: Properly handle deactivated DIDs in resolution

---

## 8. Testing Examples

### 8.1 Unit Test - DID Derivation

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_derivation() {
        // Known genesis operation and expected DID
        let genesis_json = r#"{
            "type": "plc_operation",
            "rotationKeys": ["did:key:..."],
            "verificationMethods": {"atproto": "did:key:..."},
            "alsoKnownAs": ["at://alice.test"],
            "services": {},
            "prev": null,
            "sig": "..."
        }"#;

        let op: PlcOperationBody = serde_json::from_str(genesis_json).unwrap();
        let did = derive_did(&op).unwrap();

        assert!(did.starts_with("did:plc:"));
        assert_eq!(did.len(), 32); // "did:plc:" (8) + 24 chars
    }
}
```

### 8.2 Integration Test - Full Workflow

```rust
#[tokio::test]
async fn test_create_and_resolve_did() {
    let directory = PlcDirectory::default();

    let (did, state) = create_did_for_account(
        &directory,
        "test-user.example.com",
        "https://pds.example.com",
    ).await.expect("Failed to create DID");

    // Verify DID format
    assert!(did.starts_with("did:plc:"));

    // Verify state was populated
    assert_eq!(state.also_known_as.len(), 1);
    assert!(state.also_known_as[0].contains("test-user"));

    // Verify we can resolve it back
    let resolved = directory.resolve_did_state(&did).await.expect("Failed to resolve");
    assert_eq!(resolved.did, did);
}
```

---

## 9. Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| `409 Conflict` | Invalid signature | Verify "low-S" form, ensure sig matches rotation key |
| `400 Bad Request` | Operation too large | Reduce data, ensure < 7500 bytes DAG-CBOR |
| `Invalid DID derivation` | Hash mismatch | Verify DAG-CBOR encoding matches spec, check base32 truncation |
| `Recovery not allowed` | Wrong key authority | Ensure higher-authority key is signing recovery operation |
| `Recovery expired` | Outside 72-hour window | Check operation timestamp, recovery window may have closed |
| `Signature verification failed` | High-S signature | Canonicalize to low-S using modulo arithmetic |

---

## 10. Performance Considerations

- **Key Generation**: ~100ms per key pair (network-independent)
- **DID Creation**: ~200-500ms (mostly network latency to directory)
- **Signature Verification**: ~1-5ms per operation
- **Audit Log Fetch**: Depends on operation history (could be 1-10 seconds)
- **Caching**: Cache resolved DID documents for 1-5 minutes

---

**References**:
- did:plc Specification: https://web.plc.directory/spec/v0.1/did-plc
- did:key Spec: https://w3c-ccg.github.io/did-key-spec/
- DAG-CBOR: https://ipld.io/specs/codecs/dag-cbor/spec/
- CBOR RFC 8949: https://datatracker.ietf.org/doc/html/rfc8949

