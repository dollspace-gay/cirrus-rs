# did:plc Technical Reference for Rust Implementation

**Official Specification**: https://web.plc.directory/spec/v0.1/did-plc (v0.3.0 - December 2025)

---

## 1. Overview

did:plc ("Public Ledger of Credentials") is a self-authenticating DID method developed by Bluesky Social for the AT Protocol.

**Key characteristics:**
- Self-certifying: DID is derived from the hash of the genesis operation
- Recoverable: 72-hour recovery window allows higher-authority keys to rewrite history
- Strongly-consistent: Central directory server maintains operation log
- Cryptographic: Uses ECDSA-SHA256 signing with secp256k1 or NIST P-256

**Example DID**: `did:plc:ewvi7nxzyoun6zhxrhs64oiz` (24 base32 characters)

---

## 2. DID Structure and Metadata

At any point in time, a did:plc maintains the following state:

### 2.1 Core Fields

```
{
  "did": "did:plc:xxxxxxxxxxxxxxxxxxxx",
  "rotationKeys": [                    // Priority-ordered (descending authority)
    "did:key:z...",                    // min 1, max 5 keys, no duplication
    "did:key:z..."                     // secp256k1 (k256) or NIST P-256 (p256) only
  ],
  "verificationMethods": {             // Map of service ID -> did:key
    "atproto": "did:key:z...",         // max 10 total (v0.2+)
    "otherService": "did:key:z..."     // Any valid did:key format allowed
  },
  "alsoKnownAs": [                     // Priority-ordered aliases
    "at://handle.example.com",         // AT Protocol handle
    "at://alternative-handle.test"
  ],
  "services": {                        // Service endpoint mappings
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"
    }
  }
}
```

### 2.2 Constraints

- **rotationKeys**: 1-5 keys, secp256k1 or NIST P-256 only
- **verificationMethods**: Max 10 entries (any valid did:key)
- **Operation size**: Max 7500 bytes when encoded as DAG-CBOR

### 2.3 DID Syntax

- Format: `did:plc:<24-character-identifier>`
- Identifier: base32-encoded (characters: `a-z`, `2-7`; no `0,1,8,9`)
- Length: 32 characters total (including `did:plc:` prefix)
- Case: Always lowercase (must be normalized)

---

## 3. Operations

### 3.1 Operation Types

#### Regular Operation (plc_operation)
Used for creation and updates. Contains all metadata fields.

```rust
{
  "type": "plc_operation",
  "rotationKeys": [...],
  "verificationMethods": {...},
  "alsoKnownAs": [...],
  "services": {...},
  "prev": null,           // null for genesis, CID string for updates
  "sig": "base64url..."   // Signature of unsigned operation
}
```

#### Tombstone Operation (plc_tombstone)
Deactivates a DID. Clears all metadata.

```rust
{
  "type": "plc_tombstone",
  "prev": "bafyXXX...",   // CID of previous operation (not nullable)
  "sig": "base64url..."   // Signature
}
```

#### Legacy Create Operation (deprecated, for genesis only)
Supported for backward compatibility.

```rust
{
  "type": "create",
  "signingKey": "did:key:z...",       // Single key (not array)
  "recoveryKey": "did:key:z...",      // Single key (not array)
  "handle": "alice.test",              // Bare handle (no at://)
  "service": "https://pds.example.com",// Single URL (not map)
  "prev": null,
  "sig": "base64url..."
}
```

---

## 4. Operation Signing and Hashing

### 4.1 Signing Process

1. **Create unsigned operation object**
   - Include all metadata fields
   - Include `prev` field (null for genesis)
   - Do NOT include `sig` field

2. **Encode as DAG-CBOR** (binary)
   - Use IPLD DAG-CBOR codec
   - RFC 8949 CBOR standard with restrictions

3. **Sign the bytes**
   - Use ECDSA-SHA256
   - Key used: one of the `rotationKeys` private keys
   - Signature must be in "low-S" canonical form (BIP-0062 for secp256k1)

4. **Encode signature**
   - Signature is pair of integers (r, s) from ECDSA
   - Format: 32 bytes (big-endian r) + 32 bytes (big-endian s) = 64 bytes
   - Encode as base64url (no padding, trailing bits = 0)

5. **Add to operation**
   - Add `sig` field with base64url-encoded signature

### 4.2 Signature Validation

- Verify "low-S" canonical form (reject "high-S")
- Reject non-canonical encodings
- Signature must match one of the rotation keys from previous operation
- For genesis, signature must match one of the initial rotation keys

### 4.3 CID Encoding for prev References

For referencing previous operations:

```
CIDv1 with:
  - Multibase: base32 (prefix 'b')
  - Codec: dag-cbor (code 0x71)
  - Hash: SHA-256 (code 0x12)

Format: "b" + base32(sha256(operation_bytes))
Example: "bafyreiabcd1234..."
```

---

## 5. DID Derivation (Genesis)

The DID is derived from the genesis operation hash:

```
1. Take the signed genesis operation object
2. Encode as DAG-CBOR bytes
3. Hash with SHA-256
4. Encode hash bytes as base32 (lowercase)
5. Truncate to first 24 characters
6. Prepend "did:plc:"

Pseudo-code:
did = "did:plc:" + base32Encode(sha256(dagCbor(operation))).slice(0, 24)
```

**Key point**: The DID is entirely self-certifying. Anyone can verify it was derived from the genesis operation.

---

## 6. Directory API Endpoints

### 6.1 Base URL
Default: `https://plc.directory`

### 6.2 Endpoints

#### Create/Update DID
```
POST https://plc.directory/{did}
Content-Type: application/json

Body: Signed operation object (JSON)

Response:
  - 200 OK: Operation accepted
  - 400/409: Operation rejected (invalid signature, recovery window, etc)
```

#### Resolve DID Document
```
GET https://plc.directory/{did}

Response: 200 OK
Content-Type: application/json

Body: W3C DID Document (JSON)
```

#### Resolve DID State Data
```
GET https://plc.directory/{did}/data

Response: 200 OK
Content-Type: application/json

Body: Latest state as PLC metadata object (not DID document format)
```

#### Get Current Operation CID
```
GET https://plc.directory/{did}/log/audit

Response: 200 OK
Content-Type: application/json

Body: Array of operations with metadata:
[
  {
    "cid": "bafyreiXXX...",
    "operation": {...},
    "createdAt": "2025-02-16T21:00:00.000Z",
    "nullified": false
  },
  ...
]
```

#### Bulk Export (Pagination)
```
GET https://plc.directory/export?count=100&after=0

Response: JSON lines format
Each line:
{
  "type": "sequenced_op",
  "operation": {...},
  "did": "did:plc:...",
  "cid": "bafyreiXXX...",
  "createdAt": "2025-02-16T21:00:00.000Z",
  "seq": 12345
}
```

#### Export WebSocket Stream (Real-time)
```
WebSocket: wss://plc.directory/export/stream?cursor=12345

Response: Stream of JSON objects (WebSocket message frames)
Same format as /export endpoint

Features:
  - Subscribe to new operations in real-time
  - Cursor parameter to catch up on historical ops
  - Server closes with reason if cursor invalid/outdated
```

---

## 7. DID Creation Workflow

### 7.1 Steps for PDS to Create a did:plc for New Account

```
1. GENERATE KEYS
   - Generate secp256k1 or NIST P-256 key pair for recovery (rotation)
   - Generate key for atproto verification (signing)
   - Encode as did:key

2. BUILD GENESIS OPERATION
   {
     "type": "plc_operation",
     "rotationKeys": [
       "did:key:z..." // high-authority recovery key
     ],
     "verificationMethods": {
       "atproto": "did:key:z..." // signing key for atproto
     },
     "alsoKnownAs": [
       "at://user.handle.example.com"
     ],
     "services": {
       "atproto_pds": {
         "type": "AtprotoPersonalDataServer",
         "endpoint": "https://pds.example.com"
       }
     },
     "prev": null
   }

3. SIGN OPERATION
   - Encode operation (without sig field) as DAG-CBOR
   - Sign bytes with ECDSA-SHA256 using rotation key private key
   - Ensure signature is "low-S" canonical form
   - Encode signature as base64url
   - Add "sig" field to operation

4. DERIVE DID
   - Encode signed operation as DAG-CBOR
   - Hash with SHA-256
   - Base32 encode result
   - Take first 24 characters
   - DID = "did:plc:" + truncated_hash

5. SUBMIT TO DIRECTORY
   POST https://plc.directory/{did}
   Content-Type: application/json

   Body: Signed operation object (JSON)

6. VERIFY RESPONSE
   - 200 OK: Registration successful
   - 4xx/5xx: Registration failed
     - Typical error: Invalid signature
     - Recovery key not secp256k1/p256
     - Operation size > 7500 bytes

7. STORE KEYS SECURELY
   - Store private key for recovery key
   - Store private key for atproto signing key
   - Keep for account recovery/key rotation
```

---

## 8. Account Recovery (Key Rotation)

### 8.1 Recovery Window
- **Duration**: 72 hours from when lower-authority operation was submitted
- **Authority**: Keys are ordered in `rotationKeys` array by descending authority
- **Action**: Higher-authority key can fork from earlier operation, nullifying intervening operations

### 8.2 Recovery Operation Example

```
// Original operation (to be invalidated)
const compromisedOp = {
  "type": "plc_operation",
  "rotationKeys": [
    "did:key:zLowAuthority"    // index 1 (low authority)
  ],
  "verificationMethods": {...},
  ...
}

// Recovery operation (signed by higher authority key)
const recoveryOp = {
  "type": "plc_operation",
  "rotationKeys": [
    "did:key:zHighAuthority",   // index 0 (high authority)
    "did:key:zLowAuthority"     // index 1
  ],
  "verificationMethods": {...},
  "prev": "bafyreIXXX...",      // CID of genesisOp (before compromise)
  "sig": "base64url..."         // Signed with zHighAuthority
}
```

---

## 9. DID Resolution/Validation

### 9.1 Full Validation Process

```
1. GET https://plc.directory/{did}/log/audit
   - Retrieve complete operation history

2. VALIDATE GENESIS OPERATION
   - Decode operation from legacy or modern format
   - Encode as DAG-CBOR
   - Hash with SHA-256
   - Base32 encode, truncate to 24 chars
   - Verify matches DID identifier

3. FOR EACH OPERATION IN LOG
   a. Identify valid rotation keys
      - For genesis: use operation's rotationKeys
      - For updates: use rotation keys from prev operation

   b. Verify signature
      - Remove sig field
      - Encode as DAG-CBOR
      - Try each rotation key public key
      - Verify ECDSA-SHA256 signature
      - Reject if "high-S" non-canonical
      - Must match at least one key

   c. Verify recovery constraints
      - If operation has lower authority than prev
      - Check if within 72-hour window
      - Verify no higher-authority operations exist
      - Ensure proper fork point

4. BUILD CURRENT STATE
   - Take the final valid operation
   - Extract rotationKeys, verificationMethods, alsoKnownAs, services
   - Merge into DID document if needed

5. CROSS-VALIDATE (AT Protocol context)
   - Verify alsoKnownAs handles resolve back to this DID
   - Verify PDS endpoint is reachable
   - Check atproto verification method exists
```

---

## 10. Rust Implementation Considerations

### 10.1 Key Dependencies Needed

```toml
# Cryptography
p256 = "0.13"           # NIST P-256
k256 = "0.13"           # secp256k1
sha2 = "0.10"           # SHA-256
base64-simd = "*"       # Fast base64url encoding
base32 = "*"            # Base32 encoding

# Data formats
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
ciborium = "*"          # DAG-CBOR encoding/decoding

# DID support
did-key = "*"           # did:key parsing/generation

# HTTP
reqwest = { version = "0.11", features = ["json"] }
tokio = { version = "1", features = ["full"] }

# Utility
anyhow = "1.0"
thiserror = "1.0"
```

### 10.2 Core Structures

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PlcOperation {
    #[serde(rename = "plc_operation")]
    PlcOperation {
        #[serde(skip_serializing_if = "Option::is_none")]
        prev: Option<String>,

        rotation_keys: Vec<String>,
        verification_methods: std::collections::HashMap<String, String>,
        also_known_as: Vec<String>,
        services: std::collections::HashMap<String, Service>,

        sig: String,
    },

    #[serde(rename = "plc_tombstone")]
    Tombstone {
        prev: String,
        sig: String,
    },

    #[serde(rename = "create")]
    LegacyCreate {
        signing_key: String,
        recovery_key: String,
        handle: String,
        service: String,
        prev: (),
        sig: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

#[derive(Debug, Clone)]
pub struct PlcDidState {
    pub did: String,
    pub rotation_keys: Vec<String>,
    pub verification_methods: std::collections::HashMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: std::collections::HashMap<String, Service>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlcAuditEntry {
    pub cid: String,
    pub operation: serde_json::Value,
    pub created_at: String,
    pub nullified: bool,
}
```

### 10.3 Key Functions to Implement

```rust
// Signing
fn sign_operation(operation: &UnsignedOperation, signing_key_private: &[u8])
    -> Result<String>; // Returns base64url signature

// Hashing and DID derivation
fn operation_to_dagcbor(operation: &PlcOperation) -> Result<Vec<u8>>;
fn derive_did(genesis_operation: &PlcOperation) -> Result<String>;
fn compute_cid(operation_bytes: &[u8]) -> Result<String>; // Returns CIDv1 base32

// API client
async fn submit_operation(
    client: &reqwest::Client,
    directory_url: &str,
    did: &str,
    operation: &PlcOperation,
) -> Result<()>;

async fn resolve_did_document(
    client: &reqwest::Client,
    directory_url: &str,
    did: &str,
) -> Result<serde_json::Value>; // W3C DID Document

async fn resolve_did_state(
    client: &reqwest::Client,
    directory_url: &str,
    did: &str,
) -> Result<PlcDidState>;

async fn get_audit_log(
    client: &reqwest::Client,
    directory_url: &str,
    did: &str,
) -> Result<Vec<PlcAuditEntry>>;

// Validation
fn verify_operation_signature(
    operation: &PlcOperation,
    rotation_keys: &[String],
) -> Result<()>;

fn validate_did_derivation(did: &str, genesis_op: &PlcOperation) -> Result<()>;

fn is_canonical_signature(sig_bytes: &[u8], curve: CurveType) -> bool;
```

### 10.4 Critical Implementation Details

1. **DAG-CBOR Encoding**
   - Use deterministic encoding (no key ordering variations)
   - Exclude `sig` field when signing
   - Handle null values correctly
   - Properly encode CID references in `prev` field

2. **Signature Validation**
   - Always enforce "low-S" canonical form
   - Reject "high-S" signatures
   - Support both secp256k1 and NIST P-256
   - Handle base64url padding correctly (no padding, trailing bits = 0)

3. **did:key Parsing**
   - Parse from `did:key:z...` format
   - Extract public key and algorithm
   - Support secp256k1 ("k256") and NIST P-256 ("p256") only for rotation keys
   - Support any valid did:key for verification methods

4. **Base32 Encoding**
   - Use standard base32 alphabet (a-z, 2-7)
   - Lowercase only
   - For DID derivation: truncate to 24 characters
   - For CID: include full hash

5. **HTTP Client**
   - Default directory: `https://plc.directory`
   - Timeout: reasonable value (10-30 seconds)
   - Retry logic: optional, depends on PDS requirements
   - User-Agent header: include application name/version

---

## 11. AT Protocol Integration Points

When creating a did:plc for a PDS account:

### 11.1 Required Configuration

```rust
PlcCreateRequest {
    // Rotation key for recovery (secp256k1 or p256)
    recovery_key: "did:key:z...",

    // Signing key for atproto (any valid did:key)
    atproto_signing_key: "did:key:z...",

    // Account handle
    handle: "user.pds.example.com",

    // PDS endpoint
    pds_url: "https://pds.example.com",
}
```

### 11.2 Resulting DID Document

The PDS will resolve DIDs to W3C DID Documents with:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://w3id.org/security/suites/ecdsa-2019/v1"
  ],
  "id": "did:plc:...",
  "alsoKnownAs": ["at://user.pds.example.com"],
  "verificationMethod": [
    {
      "id": "#atproto",
      "type": "Multikey",
      "controller": "did:plc:...",
      "publicKeyMultibase": "z..."
    }
  ],
  "service": [
    {
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": "https://pds.example.com"
    }
  ]
}
```

---

## 12. Error Handling

### 12.1 Common Rejection Reasons

```
400 Bad Request:
  - Invalid JSON syntax
  - Operation size > 7500 bytes
  - Invalid cryptographic algorithm (not secp256k1/p256 for rotation)
  - Invalid base64url encoding

409 Conflict:
  - Signature validation failed
  - Rotation key not in previous operation's keys
  - Operation within recovery window with wrong authority order
  - DID identifier mismatch (calc != header)

500 Server Error:
  - PLC server internal error
  - Rare, but handle gracefully
```

### 12.2 Validation Checklist

- [ ] rotationKeys: 1-5 secp256k1/p256 keys in did:key format
- [ ] verificationMethods: max 10, any valid did:key format
- [ ] alsoKnownAs: optional, array of URI strings
- [ ] services: optional, map of type/endpoint pairs
- [ ] prev: null for genesis, CID string for updates
- [ ] sig: base64url-encoded ECDSA signature
- [ ] Operation size: < 7500 bytes when DAG-CBOR encoded
- [ ] DID identifier: exactly 24 base32 characters (a-z, 2-7)
- [ ] Signature: "low-S" canonical form, verified against rotation key

---

## 13. References

- Official Specification: https://web.plc.directory/spec/v0.1/did-plc
- GitHub Repository: https://github.com/did-method-plc/did-method-plc
- AT Protocol Specs: https://atproto.com/specs/did
- W3C DID Core: https://www.w3.org/TR/did-core/
- did:key Spec: https://w3c-ccg.github.io/did-key-spec/
- CID Spec: https://github.com/multiformats/cid
- DAG-CBOR: https://ipld.io/specs/codecs/dag-cbor/spec/
- CBOR RFC: https://datatracker.ietf.org/doc/html/rfc8949
- ECDSA BIP-0062: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
- base32 Multibase: https://github.com/multiformats/multibase
- base64url RFC: https://www.rfc-editor.org/rfc/rfc4648.html#section-5

---

## 14. Quick Reference Checklist for Implementation

### DID Creation (PDS Registration)
- [ ] Generate secp256k1/p256 recovery key pair
- [ ] Generate key pair for atproto signing
- [ ] Convert public keys to did:key format
- [ ] Create PlcOperation with prev=null
- [ ] Encode as DAG-CBOR (exclude sig field)
- [ ] Sign with recovery key private key
- [ ] Ensure "low-S" canonical signature form
- [ ] Encode signature as base64url
- [ ] Add sig field to operation
- [ ] Encode full operation as DAG-CBOR
- [ ] Hash with SHA-256
- [ ] Base32 encode hash
- [ ] Truncate to 24 characters
- [ ] Generate DID: "did:plc:" + truncated hash
- [ ] POST signed operation to plc.directory/{did}
- [ ] Handle 200 success or error responses

### DID Validation
- [ ] Fetch operation log from plc.directory/{did}/log/audit
- [ ] Validate genesis operation DID derivation
- [ ] Verify each operation signature against rotation keys
- [ ] Check "low-S" canonical signature form
- [ ] Validate recovery window constraints
- [ ] Build final state from latest valid operation
- [ ] Convert to W3C DID Document format

### Key Rotation
- [ ] Get current DID state and latest operation CID
- [ ] Create new PlcOperation with updated rotationKeys
- [ ] Set prev to CID of previous operation
- [ ] Sign with current rotation key
- [ ] POST to plc.directory/{did}

### Account Recovery
- [ ] Get audit log to find compromised operation
- [ ] Get CID of last "good" operation before compromise
- [ ] Create recovery operation with prev=CID_of_good_operation
- [ ] Sign with higher-authority rotation key
- [ ] POST to plc.directory/{did}
- [ ] Verify within 72-hour window

---

**Document Version**: Based on did:plc Specification v0.3.0 (December 2025)

**Last Updated**: February 16, 2026

**Scope**: Complete technical reference for implementing did:plc creation, validation, and resolution in Rust

