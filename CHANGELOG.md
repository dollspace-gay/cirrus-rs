# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Changed
- Write CHANGELOG and README (#75)

### Added
- Full integration test suite: 45 HTTP-level tests covering all 27 XRPC endpoints (#74)
- Refresh token scope validation in auth middleware — access endpoints reject refresh-scoped JWTs (#73)
- Input validation for record keys (rkey) and collection NSIDs with path traversal protection (#73)
- SSRF protection in handle resolver — blocks private IPs, loopback, cloud metadata, `.local`/`.onion` (#73)
- Rate limiting on write endpoints (`createRecord`, `putRecord`, `deleteRecord`) (#73)
- Payload size limit (64KB) on record creation (#73)

### Security
- **CRITICAL**: Fixed refresh tokens (90-day lifetime) being accepted as access tokens on all authenticated endpoints
- **HIGH**: Fixed path traversal via crafted rkey (`../../../etc/passwd`) and collection names
- **HIGH**: Fixed SSRF in `resolveHandle` — attacker could probe internal networks via handle resolution
- **HIGH**: Fixed missing rate limiting on write endpoints allowing record flooding

## [0.1.0] - 2026-01-04

Initial implementation of Cirrus PDS — a single-user AT Protocol Personal Data Server in Rust.

### Added

#### Core Infrastructure
- Workspace with 4 crates: `cirrus-common`, `cirrus-oauth`, `cirrus-pds`, `cirrus-cli`
- SQLite-backed repository storage with WAL mode
- Merkle Search Tree (MST) implementation for AT Protocol repo structure
- CAR (Content Addressable aRchive) file reader and writer
- CBOR serialization for AT Protocol data model
- CID (Content Identifier) computation and validation

#### Server & XRPC Endpoints (27 total)
- Axum-based HTTP server with CORS and tracing
- **Server**: `describeServer`, `createSession`, `refreshSession`, `getSession`, `deleteSession`, `activateAccount`, `deactivateAccount`, `checkAccountStatus`
- **Repo**: `describeRepo`, `getRecord`, `listRecords`, `createRecord`, `putRecord`, `deleteRecord`, `uploadBlob`
- **Sync**: `getHead`, `getLatestCommit`, `getBlob`, `getRepo`, `subscribeRepos` (WebSocket firehose)
- **Identity**: `resolveHandle` (DNS TXT + HTTP well-known)
- **Actor**: `getPreferences`, `putPreferences`
- **Well-known**: `/.well-known/atproto-did`, `/.well-known/did.json`
- **Health**: `/health`

#### Authentication & Authorization
- JWT-based session auth (HS256) with access/refresh token flow
- `RequireAuth` and `RequireAdmin` axum extractors
- Session JWT and service JWT support
- bcrypt password hashing and verification
- Configurable JWT secret, DID, handle, and public key via CLI args or env vars

#### OAuth 2.0
- OAuth SQLite storage adapter for tokens, sessions, and client metadata
- DPoP (Demonstration of Proof-of-Possession) token verification
- Pushed Authorization Requests (PAR)
- PKCE (Proof Key for Code Exchange) support

#### Identity
- `did:web` document generation and serving
- Handle resolution via DNS TXT records (`_atproto.{handle}`)
- Handle resolution via HTTP well-known (`/.well-known/atproto-did`)

#### Storage
- `MemoryBlobStore` and `DiskBlobStore` implementations
- Blob storage with CID-based content addressing and 2-char prefix sharding
- 5MB blob size limit
- SQLite storage for repo blocks, preferences, and account state

#### CLI (`cirrus-cli`)
- `pds init` — interactive PDS initialization
- `pds serve` — start the PDS server with full config options
- `pds migrate` — export/import account via CAR files
- `pds activate` / `pds deactivate` — account lifecycle management
- `pds secret key|jwt|password` — generate signing keys, JWT secrets, password hashes
- Environment variable support for all config (`PDS_DID`, `PDS_HANDLE`, `PDS_JWT_SECRET`, etc.)

#### Rate Limiting
- IP-keyed token bucket rate limiting via `governor`
- Configurable general (30 req/s) and login (5 req/s) rate limits with burst multipliers
- Applied to session creation and all write endpoints

#### Repo Operations
- Signed commits with secp256k1 keys
- Record CRUD with MST-based storage
- Firehose event sequencing for `subscribeRepos`
- Lexicon validation with permissive mode for unknown collections

#### Testing
- 165 unit tests across all crates
- Comprehensive test coverage for crypto, JWT, storage, auth, MST, CAR, and CBOR modules
