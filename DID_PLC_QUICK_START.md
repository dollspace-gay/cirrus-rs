# did:plc Quick Start Guide

**TL;DR for implementing did:plc DID creation in a PDS**

---

## What is did:plc?

did:plc is a **self-certifying, recoverable DID method** for the AT Protocol.

- **Self-certifying**: The DID identifier is derived from a hash of the genesis operation
- **Recoverable**: 72-hour window to recover from key compromise using higher-authority keys
- **Strongly-consistent**: Central directory maintains authoritative operation log

Example DID: `did:plc:ewvi7nxzyoun6zhxrhs64oiz`

---

## High-Level Workflow for PDS Account Creation

```
1. Generate two key pairs:
   - Recovery key (secp256k1 or NIST P-256) for account recovery
   - Signing key (any valid did:key) for atproto operations

2. Build genesis operation with metadata:
   - rotationKeys: [recovery_key_did]
   - verificationMethods: {atproto: signing_key_did}
   - alsoKnownAs: [at://user.handle.pds.com]
   - services: {atproto_pds: {endpoint: https://pds.com}}

3. Sign operation:
   - Encode operation as DAG-CBOR (without sig field)
   - Sign bytes with ECDSA-SHA256
   - Canonicalize signature to "low-S" form
   - Base64url encode signature

4. Derive DID:
   - Encode signed operation as DAG-CBOR
   - SHA-256 hash the bytes
   - Base32 encode, truncate to 24 chars
   - DID = "did:plc:" + truncated_hash

5. Submit to directory:
   - POST signed operation to https://plc.directory/{did}
   - Receive 200 OK if successful

6. Store keys securely for account recovery
```

---

## Key Facts

### Operation Structure

All operations have these fields:
- `type`: "plc_operation" or "plc_tombstone" or "create" (legacy)
- `rotationKeys`: Array of 1-5 did:key strings (secp256k1/p256 only)
- `verificationMethods`: Map of service -> did:key (any type allowed)
- `alsoKnownAs`: Array of identity URIs (at://handle, etc)
- `services`: Map of service -> {type, endpoint}
- `prev`: CID of previous operation (null for genesis)
- `sig`: base64url ECDSA-SHA256 signature

### Critical Details

| Aspect | Details |
|--------|---------|
| **DID Format** | `did:plc:` + 24 base32 chars (a-z, 2-7) |
| **Rotation Keys** | secp256k1 ("k256") or NIST P-256 ("p256") only |
| **Verification Methods** | Any valid did:key format |
| **Max Operation Size** | 7500 bytes (DAG-CBOR encoded) |
| **Recovery Window** | 72 hours |
| **Directory URL** | https://plc.directory (default) |
| **Signing Algorithm** | ECDSA-SHA256 with "low-S" canonical form |
| **Encoding Format** | DAG-CBOR for hashing/signing, JSON for submission |

---

## Minimal Code Example (Pseudocode)

```rust
// 1. Generate keys
let (recovery_key_did, recovery_private) = generate_k256_key()?;
let (signing_key_did, _) = generate_p256_key()?;

// 2. Build operation
let operation = PlcOperationBody {
    op_type: "plc_operation",
    rotation_keys: vec![recovery_key_did.clone()],
    verification_methods: {
        "atproto": signing_key_did.clone()
    },
    also_known_as: vec!["at://alice.example.com"],
    services: {
        "atproto_pds": Service {
            service_type: "AtprotoPersonalDataServer",
            endpoint: "https://pds.example.com"
        }
    },
    prev: None,
    sig: "", // Will be filled in next step
};

// 3. Sign operation
let unsigned = to_unsigned_op(&operation);
let cbor_bytes = dagcbor_encode(&unsigned);
let sig_bytes = ecdsa_sign(&cbor_bytes, &recovery_private);
let sig_canonical = ensure_low_s(&sig_bytes);
operation.sig = base64url_encode(&sig_canonical);

// 4. Derive DID
let signed_cbor = dagcbor_encode(&operation);
let hash = sha256(&signed_cbor);
let b32_hash = base32_encode(&hash);
let did = format!("did:plc:{}", &b32_hash[0..24]);

// 5. Submit to directory
let client = reqwest::Client::new();
let response = client
    .post(&format!("https://plc.directory/{}", did))
    .json(&operation)
    .send()
    .await?;

if response.status() == 200 {
    println!("DID created: {}", did);
} else {
    println!("Error: {}", response.status());
}
```

---

## Directory API Endpoints

### Create/Update DID
```
POST https://plc.directory/{did}
Content-Type: application/json

Body: Signed operation object
Response: 200 OK or error
```

### Resolve DID Document
```
GET https://plc.directory/{did}
Response: W3C DID Document (JSON)
```

### Get DID State Data
```
GET https://plc.directory/{did}/data
Response: PLC state object (metadata fields)
```

### Get Audit Log
```
GET https://plc.directory/{did}/log/audit
Response: Array of operation entries with timestamps
```

### Bulk Export
```
GET https://plc.directory/export?count=100&after=0
Response: JSON lines, one operation per line
```

### Real-time Stream
```
WebSocket wss://plc.directory/export/stream?cursor=0
Response: Stream of operations as they're submitted
```

---

## Common Errors and Fixes

| Error | Cause | Fix |
|-------|-------|-----|
| `400 Bad Request` | Invalid JSON or operation too large | Verify JSON syntax, limit metadata size |
| `409 Conflict` | Signature validation failed | Ensure "low-S" form, verify key matches, check prev CID |
| `404 Not Found` | DID not found | Create DID first or verify identifier |
| `Signature invalid` | Wrong key or encoding | Use correct private key, base64url with no padding |
| `Recovery not allowed` | Wrong authority or outside window | Use higher-authority key, must be within 72 hours |

---

## What to Implement in Rust

### Core Functions
1. **Key generation**: Generate secp256k1/p256 key pairs, convert to did:key
2. **DAG-CBOR encoding**: Serialize operations consistently for signing/hashing
3. **Signing**: ECDSA-SHA256 with "low-S" canonicalization
4. **DID derivation**: SHA-256 hash, base32 encode, truncate
5. **CID computation**: For prev field references
6. **HTTP client**: POST operations, GET resolution

### Dependencies
```toml
k256 = "0.13"               # secp256k1
p256 = "0.13"               # NIST P-256
sha2 = "0.10"               # SHA-256
ciborium = "*"              # DAG-CBOR
base32 = "*"                # Base32 encoding
base64-simd = "*"           # base64url encoding
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
```

---

## Validation Checklist

Before submitting a DID operation:

- [ ] rotationKeys: 1-5 keys, secp256k1/p256, valid did:key format
- [ ] verificationMethods: max 10, any valid did:key format
- [ ] alsoKnownAs: valid URIs (e.g., `at://handle`)
- [ ] services: valid type and endpoint strings
- [ ] prev: null for genesis, valid CID for updates
- [ ] sig: base64url-encoded, 64 bytes (32r + 32s), canonical "low-S" form
- [ ] Operation size: < 7500 bytes when DAG-CBOR encoded
- [ ] DID format: exactly 32 chars (8 for "did:plc:" + 24 base32)

---

## Testing Steps

1. **Generate keys**
   - Create secp256k1 and p256 key pairs
   - Convert to did:key format
   - Verify format is correct

2. **Create operation**
   - Build operation object
   - Verify all required fields present
   - Validate field types

3. **Sign operation**
   - Encode as DAG-CBOR
   - Sign bytes
   - Ensure "low-S" canonicalization
   - Verify signature verifies with public key

4. **Derive DID**
   - Hash genesis operation
   - Base32 encode, truncate
   - Verify DID format

5. **Submit to directory**
   - POST to plc.directory
   - Handle success (200) and errors (400, 409)
   - Verify operation appears in audit log

6. **Resolve DID**
   - GET from plc.directory/{did}
   - Verify DID document contains expected data
   - Check state data matches what you submitted

---

## Performance Targets

- Key generation: ~100ms
- DID creation (submit + verify): ~500ms-2s (mostly network)
- Signature verification: ~1-5ms
- DID resolution: ~100-500ms (network dependent)

---

## Security Considerations

### Protect Private Keys
- Store recovery key private in secure storage (encrypted at rest)
- Never transmit private keys over network
- Generate unique key pairs per account

### Signature Validation
- Always verify "low-S" canonical form
- Reject non-canonical signatures
- Verify signature matches rotation key

### Handle Recovery
- Understand 72-hour recovery window
- Keep higher-authority keys safe
- Document key recovery procedure

### Audit Logs
- Handle history is public
- PDS URLs are permanently visible
- alsoKnownAs values cannot be deleted

---

## AT Protocol Integration

When creating a did:plc for a new atproto account:

```json
{
  "type": "plc_operation",
  "rotationKeys": [
    "did:key:z..."  // Recovery key
  ],
  "verificationMethods": {
    "atproto": "did:key:z..."  // Signing key for repo operations
  },
  "alsoKnownAs": [
    "at://username.example.com"  // Account handle
  ],
  "services": {
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"  // PDS endpoint
    }
  },
  "prev": null,
  "sig": "..."
}
```

The signing key (`verificationMethods.atproto`) is what users use to sign repository updates.

---

## References

- **Official Spec**: https://web.plc.directory/spec/v0.1/did-plc
- **GitHub**: https://github.com/did-method-plc/did-method-plc
- **AT Protocol**: https://atproto.com
- **did:key Spec**: https://w3c-ccg.github.io/did-key-spec/
- **DAG-CBOR**: https://ipld.io/specs/codecs/dag-cbor/spec/
- **CBOR RFC**: https://datatracker.ietf.org/doc/html/rfc8949
- **W3C DID Core**: https://www.w3.org/TR/did-core/

---

## Next Steps

1. Read the full technical reference: `/DID_PLC_TECHNICAL_REFERENCE.md`
2. Review implementation guide with code examples: `/DID_PLC_IMPLEMENTATION_GUIDE.md`
3. Check API reference for directory endpoints: `/DID_PLC_API_REFERENCE.md`
4. Start implementing in your PDS

---

**Version**: 1.0
**Last Updated**: February 16, 2026
**Specification**: did:plc v0.3.0

