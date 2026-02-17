# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed
- Account deletion emits empty commit instead of proper #tombstone event (#102)
- Add atomic repo write transactions (#83)

### Changed
- Delete orphaned test account from Bluesky network (#101)
- Smoke test email + deletion features via ngrok (#100)
- Epic: Testing & Validation (#5)
- Firehose tests (8+ tests) (#65)
- E2E federation tests (#71)
- Bluesky protocol compliance tests (11+ tests) (#69)
- OAuth flow tests (#70)
- Service auth tests (3+ tests) (#68)
- Lexicon validation tests (8+ tests) (#67)
- Blob storage tests (10+ tests) (#66)
- Migration tests (9+ tests) (#64)
- Session auth tests (15+ tests) (#63)
- XRPC endpoint tests (32+ tests) (#62)
- Storage layer tests (16+ tests) (#61)
- Integration test harness (#60)
- Unit test framework setup (#59)
- Epic: CLI Tools (cirrus-cli) (#4)
- create-pds scaffolding CLI (#58)
- .env file management (#56)
- Wrangler integration utilities (#55)
- Epic: Core PDS Library (cirrus-pds) (#3)
- XRPC proxy for unknown methods (#46)
- Epic: OAuth 2.1 Provider Library (cirrus-oauth) (#2)
- Consent UI HTML rendering (#21)
- Add did.json well-known route and test live PDS federation (#72)
- Epic: Project Infrastructure & Common Libraries (#1)
- Add read-after-write consistency layer (#79)
- Add appview pipethrough layer for proxying app.bsky.* read requests (#78)
- Add getServiceAuth endpoint for inter-service JWT creation (#77)
- Write CHANGELOG and README (#75)

### Added
- Add labeler/moderation service integration (#113)
- Add multi-user hosting support (#112)
- Add did:plc as primary DID method (#109)
- Add S3-compatible blob storage backend (#110)
- Add full account status management (suspended, takendown states) (#111)
- Add importRepo and listMissingBlobs endpoints for account migration (#108)
- Implement com.atproto.admin.* API endpoints (#106)
- Add reserveSigningKey endpoint (#107)
- Add invite code XRPC endpoints (createInviteCode, createInviteCodes, getAccountInviteCodes) (#105)
- Add account deletion flow (requestAccountDelete + deleteAccount) (#93)
- Add email system for verification and password reset (#89)
- Add image processing pipeline for blob uploads (#97)
- Add invite code system (#96)
- Add configuration validation on server startup (#98)
- Add moderation report endpoint (createReport) (#95)
- Add PLC operation endpoints for DID updates (#92)
- Add createAccount endpoint for XRPC account creation (#94)
- Add updateHandle endpoint (#91)
- Add database migration system (#90)
- Add app password support (#88)
- Add blob garbage collection and reference tracking (#86)
- Implement appview pipethrough and service auth (#76)
- Implement missing sync endpoints (getBlocks, listRepos, listBlobs) (#87)
- Add crawler/relay notification via requestCrawl (#84)
- Implement applyWrites for atomic batch record operations (#80)
- Implement incremental MST updates instead of full rebuild (#81)
- Add record indexing table for efficient queries (#85)
- Implement sequencer persistence and cursor-based firehose replay (#82)
- Full integration test suite: 45 HTTP-level tests covering all 27 XRPC endpoints (#74)
- Refresh token scope validation in auth middleware — access endpoints reject refresh-scoped JWTs (#73)
- Input validation for record keys (rkey) and collection NSIDs with path traversal protection (#73)
- SSRF protection in handle resolver — blocks private IPs, loopback, cloud metadata, `.local`/`.onion` (#73)
- Rate limiting on write endpoints (`createRecord`, `putRecord`, `deleteRecord`) (#73)
- Payload size limit (64KB) on record creation (#73)

### Security
- Add refresh token persistence and reuse detection (#99)
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
