# did:plc Documentation Index

Complete technical documentation for implementing AT Protocol did:plc DID creation and resolution in Rust.

---

## Documentation Files

### 1. **DID_PLC_QUICK_START.md** (9.6 KB)
**Start here!** High-level overview with minimal code and quick reference.

**Covers:**
- What is did:plc?
- High-level workflow
- Key facts and critical details
- Common errors and fixes
- Validation checklist

**Best for:** Quick orientation, decision-making, overview

---

### 2. **DID_PLC_TECHNICAL_REFERENCE.md** (20 KB)
Comprehensive technical specification covering all aspects of did:plc.

**Covers:**
- Complete DID structure and metadata fields
- Operation types and serialization
- Signing and hashing (DAG-CBOR, ECDSA-SHA256)
- DID derivation from genesis operation
- Directory API endpoints (POST, GET, WebSocket)
- Complete DID creation/update/recovery workflows
- Rust implementation considerations
- Error handling and validation
- AT Protocol integration points

**Best for:** Deep understanding, reference, implementation planning

---

### 3. **DID_PLC_IMPLEMENTATION_GUIDE.md** (25 KB)
Practical Rust code examples for all major operations.

**Covers:**
- JSON operation structure examples
- Rust struct definitions for operations
- Key generation (secp256k1 and NIST P-256)
- Signing operations with DAG-CBOR encoding
- DID derivation and CID computation
- HTTP client setup and API interactions
- Complete DID creation workflow
- Signature validation
- Unit and integration test examples
- Common errors and solutions

**Best for:** Implementation, code reference, testing

---

### 4. **DID_PLC_API_REFERENCE.md** (17 KB)
Complete API documentation for the PLC Directory service.

**Covers:**
- All directory endpoints (POST, GET, WebSocket)
- Request/response format specifications
- Query parameters and headers
- Error codes and responses
- Rate limiting and CORS policy
- Complete workflow examples with curl
- Pagination patterns
- JSON lines export format
- Real-time WebSocket streaming
- Error troubleshooting

**Best for:** API integration, endpoint reference, debugging

---

## Quick Navigation

### By Task

#### "I need to understand did:plc concepts"
1. Read: **DID_PLC_QUICK_START.md** (15 min)
2. Read: **DID_PLC_TECHNICAL_REFERENCE.md** sections 1-6 (30 min)

#### "I need to implement DID creation in Rust"
1. Read: **DID_PLC_QUICK_START.md** (15 min)
2. Reference: **DID_PLC_TECHNICAL_REFERENCE.md** sections 10.2-10.4 (15 min)
3. Code: **DID_PLC_IMPLEMENTATION_GUIDE.md** sections 2-5 (2-4 hours)
4. Test: **DID_PLC_IMPLEMENTATION_GUIDE.md** section 8 (1-2 hours)

#### "I need to implement API integration"
1. Reference: **DID_PLC_API_REFERENCE.md** sections 1-6 (30 min)
2. Code: **DID_PLC_IMPLEMENTATION_GUIDE.md** section 4 (1-2 hours)

#### "I need to debug a signature validation failure"
1. Check: **DID_PLC_TECHNICAL_REFERENCE.md** section 4 (Signing)
2. Check: **DID_PLC_IMPLEMENTATION_GUIDE.md** section 6 (Validation)
3. Check: **DID_PLC_API_REFERENCE.md** section 12 (Troubleshooting)

#### "I need to understand key rotation/recovery"
1. Read: **DID_PLC_TECHNICAL_REFERENCE.md** section 8 (Recovery)
2. Example: **DID_PLC_IMPLEMENTATION_GUIDE.md** section 5 (Workflow)

---

## Key Concepts Summary

### DID Structure
- **DID**: `did:plc:` + 24 base32 characters
- **Self-certifying**: Identifier is hash of genesis operation
- **Self-authenticating**: Contains cryptographic proof of authority

### Operations
- **Genesis** (plc_operation, prev=null): Initial DID creation
- **Update** (plc_operation, prev=CID): Modify metadata or rotate keys
- **Tombstone** (plc_tombstone): Deactivate DID
- **Legacy Create**: Backward compatibility for old DIDs

### Fields
| Field | Type | Purpose |
|-------|------|---------|
| rotationKeys | Array | Control authority (1-5 secp256k1/p256 keys) |
| verificationMethods | Map | Service-specific signing keys (any did:key) |
| alsoKnownAs | Array | Identity aliases (at://, did://, etc) |
| services | Map | Service endpoints (PDS, etc) |
| prev | CID | Reference to previous operation (null for genesis) |
| sig | base64url | ECDSA-SHA256 signature |

### Cryptography
- **Key curves**: secp256k1 (recovery), NIST P-256, others (verification)
- **Signing**: ECDSA-SHA256, "low-S" canonical form required
- **Hashing**: SHA-256 for DID derivation and CID
- **Encoding**: DAG-CBOR (binary), then base32/base64url for strings

### Recovery
- **Window**: 72 hours from operation timestamp
- **Authority**: Ordered by rotationKeys array index (lower = higher)
- **Mechanism**: Sign operation pointing to pre-compromise fork point

### Directory API
- **Base URL**: https://plc.directory
- **Create/Update**: POST /{did}
- **Resolve**: GET /{did} (DID document) or GET /{did}/data (state)
- **History**: GET /{did}/log/audit or WebSocket wss://.../export/stream
- **Bulk**: GET /export?count=X&after=Y

---

## Implementation Checklist

### Phase 1: Planning & Understanding
- [ ] Read DID_PLC_QUICK_START.md
- [ ] Review DID_PLC_TECHNICAL_REFERENCE.md sections 1-3
- [ ] Understand operation structure and fields
- [ ] Understand key concepts (DID derivation, signing, recovery)

### Phase 2: Dependencies & Setup
- [ ] Add Rust dependencies (k256, p256, sha2, ciborium, etc)
- [ ] Create Rust structs for operations (review section 2.1)
- [ ] Set up HTTP client (reqwest)
- [ ] Create test fixtures

### Phase 3: Core Cryptography
- [ ] Implement key generation (secp256k1, NIST P-256)
- [ ] Implement did:key encoding
- [ ] Implement DAG-CBOR encoding
- [ ] Implement ECDSA signing with "low-S" canonicalization
- [ ] Implement signature verification
- [ ] Test with known vectors

### Phase 4: DID Operations
- [ ] Implement DID derivation (SHA-256 → base32 → truncate)
- [ ] Implement CID computation for prev references
- [ ] Implement operation signing (unsigned → signed)
- [ ] Implement operation serialization (Rust → JSON)

### Phase 5: Directory API
- [ ] Implement POST /{did} (operation submission)
- [ ] Implement GET /{did} (DID document resolution)
- [ ] Implement GET /{did}/data (state resolution)
- [ ] Implement GET /{did}/log/audit (history)
- [ ] Error handling for all responses

### Phase 6: High-level Workflows
- [ ] Implement DID creation workflow
- [ ] Implement DID update workflow (key rotation)
- [ ] Implement DID recovery workflow
- [ ] Implement handle resolution

### Phase 7: Testing & Validation
- [ ] Unit tests for cryptographic operations
- [ ] Integration tests with live directory
- [ ] Test error cases (invalid sig, recovery window, etc)
- [ ] Achieve 80%+ test coverage
- [ ] Validate against official test vectors

### Phase 8: Documentation & Polish
- [ ] Document public API
- [ ] Add examples to docstrings
- [ ] Create error types with good messages
- [ ] Add logging for debugging
- [ ] Create integration guide for PDS

---

## Common Questions

### Q: Why is the DID self-certifying?
**A:** The DID is the hash of the genesis operation, which contains all the public keys needed to verify authority. Anyone can independently verify the DID by re-hashing the operation.

### Q: What happens if I lose the recovery key?
**A:** You're permanently locked out of that DID. This is by design - there's no master override. Best practice is to securely backup the recovery key.

### Q: Can I rotate my keys?
**A:** Yes! Create an update operation with new rotationKeys pointing to the previous operation. The new operation must be signed by a current rotation key.

### Q: What's the "low-S" requirement?
**A:** ECDSA signatures can have two valid representations (high-S and low-S forms). Only low-S is allowed to prevent signature malleability attacks.

### Q: How does account recovery work?
**A:** If a low-authority key is compromised, a higher-authority key can create a recovery operation within 72 hours that points to the last known-good operation, invalidating the compromised operations.

### Q: Do I need to run my own PLC directory?
**A:** No, you can use the default at https://plc.directory. But for enterprise deployments, you could run a replica or mirror.

### Q: What's the difference between rotationKeys and verificationMethods?
**A:** rotationKeys control the DID (can update it), while verificationMethods are just service-specific keys listed in the DID document. The atproto key is a verificationMethod.

### Q: Can I have multiple handles?
**A:** Not currently, but it's under consideration for future versions. Today, alsoKnownAs should have one primary at:// handle.

---

## Resources

### Official Sources
- **Specification**: https://web.plc.directory/spec/v0.1/did-plc
- **Repository**: https://github.com/did-method-plc/did-method-plc
- **AT Protocol**: https://atproto.com
- **W3C DID Core**: https://www.w3.org/TR/did-core/

### Standards Referenced
- **did:key**: https://w3c-ccg.github.io/did-key-spec/
- **DAG-CBOR**: https://ipld.io/specs/codecs/dag-cbor/spec/
- **CBOR**: https://datatracker.ietf.org/doc/html/rfc8949
- **CID**: https://github.com/multiformats/cid
- **Multibase**: https://github.com/multiformats/multibase
- **ECDSA**: https://datatracker.ietf.org/doc/html/rfc4754
- **BIP-0062**: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki

### Related Tools
- **did-method-plc**: Reference implementation (TypeScript)
- **plc.directory**: Official directory service
- **atproto**: Full AT Protocol implementation

---

## Document Versions

| File | Version | Last Updated | Size |
|------|---------|--------------|------|
| DID_PLC_QUICK_START.md | 1.0 | Feb 16, 2026 | 9.6 KB |
| DID_PLC_TECHNICAL_REFERENCE.md | 1.0 | Feb 16, 2026 | 20 KB |
| DID_PLC_IMPLEMENTATION_GUIDE.md | 1.0 | Feb 16, 2026 | 25 KB |
| DID_PLC_API_REFERENCE.md | 1.0 | Feb 16, 2026 | 17 KB |
| DID_PLC_DOCS_INDEX.md | 1.0 | Feb 16, 2026 | 10 KB |

**Based on**: did:plc Specification v0.3.0 (December 2025)

---

## How to Use This Documentation

1. **First time?** Start with DID_PLC_QUICK_START.md
2. **Need details?** Go to DID_PLC_TECHNICAL_REFERENCE.md
3. **Ready to code?** Reference DID_PLC_IMPLEMENTATION_GUIDE.md
4. **Integrating APIs?** Check DID_PLC_API_REFERENCE.md
5. **Lost?** You're reading DID_PLC_DOCS_INDEX.md (this file!)

---

## Feedback & Updates

These documents are based on the official did:plc specification v0.3.0 (December 2025). For the latest specification and updates:

- Visit: https://web.plc.directory/spec/v0.1/did-plc
- GitHub Issues: https://github.com/did-method-plc/did-method-plc/issues
- AT Protocol Docs: https://atproto.com

---

**Created**: February 16, 2026

**Purpose**: Complete technical reference for implementing did:plc DID creation and resolution in Rust

**Status**: Production-ready documentation

