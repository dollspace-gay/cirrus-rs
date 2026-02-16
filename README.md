# Cirrus PDS

A single-user [AT Protocol](https://atproto.com/) Personal Data Server written in Rust.

Cirrus federates with the Bluesky network — posts created on this PDS appear on Bluesky and other AT Protocol services. It is designed to run as a lightweight, self-hosted alternative to the reference TypeScript PDS.

## Features

- **27 XRPC endpoints** — full server, repo, sync, identity, and actor APIs
- **WebSocket firehose** — `subscribeRepos` for real-time repo events
- **Signed commits** — secp256k1 signed Merkle Search Tree repo structure
- **`did:web` identity** — automatic DID document serving
- **Handle resolution** — DNS TXT and HTTP well-known methods
- **OAuth 2.0** — DPoP-bound tokens, PAR, PKCE
- **SQLite storage** — WAL mode, single-file database
- **Disk blob storage** — CID-addressed with sharded directories
- **Rate limiting** — IP-keyed token bucket via `governor`
- **210 tests** — unit + HTTP-level integration tests

## Architecture

```
cirrus-rs/
├── cirrus-common    # CID, CAR, CBOR, crypto, JWT utilities
├── cirrus-oauth     # OAuth 2.0 provider with DPoP support
├── cirrus-pds       # PDS server: routes, storage, auth, MST, repo
└── cirrus-cli       # CLI: init, serve, migrate, activate, secret
```

## Quick Start

### Prerequisites

- Rust 1.75+
- A domain name (for `did:web` and handle resolution)

### 1. Build

```bash
cargo build --release
```

### 2. Generate secrets

```bash
# Signing key (secp256k1)
cargo run -p cirrus-cli -- secret key

# JWT secret
cargo run -p cirrus-cli -- secret jwt

# Password hash
cargo run -p cirrus-cli -- secret password "your-password-here"
```

### 3. Run the server

```bash
cargo run -p cirrus-cli -- serve \
  --did "did:web:your-domain.com" \
  --handle "your-handle.your-domain.com" \
  --hostname "your-domain.com" \
  --signing-key "$SIGNING_KEY" \
  --public-key "$PUBLIC_KEY" \
  --jwt-secret "$JWT_SECRET" \
  --password-hash "$PASSWORD_HASH" \
  --db /path/to/pds.db \
  --bind 0.0.0.0:2583
```

All flags can be set via environment variables (`PDS_DID`, `PDS_HANDLE`, `PDS_HOSTNAME`, `PDS_SIGNING_KEY`, `PDS_PUBLIC_KEY`, `PDS_JWT_SECRET`, `PDS_PASSWORD_HASH`, `PDS_DB`, `PDS_BIND`).

### 4. Verify

```bash
# Health check
curl http://localhost:2583/health

# Server description
curl http://localhost:2583/xrpc/com.atproto.server.describeServer

# Authenticate
curl -X POST http://localhost:2583/xrpc/com.atproto.server.createSession \
  -H "Content-Type: application/json" \
  -d '{"identifier":"your-handle.your-domain.com","password":"your-password-here"}'
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `pds init` | Interactive PDS setup |
| `pds serve` | Start the PDS server |
| `pds migrate` | Export/import account via CAR file |
| `pds activate` | Activate a deactivated account |
| `pds deactivate` | Deactivate the account on the network |
| `pds secret key` | Generate a secp256k1 signing key |
| `pds secret jwt` | Generate a JWT secret |
| `pds secret password <pw>` | Hash a password with bcrypt |

## XRPC Endpoints

### Server (`com.atproto.server`)
`describeServer` `createSession` `refreshSession` `getSession` `deleteSession` `activateAccount` `deactivateAccount` `checkAccountStatus`

### Repo (`com.atproto.repo`)
`describeRepo` `getRecord` `listRecords` `createRecord` `putRecord` `deleteRecord` `uploadBlob`

### Sync (`com.atproto.sync`)
`getHead` `getLatestCommit` `getBlob` `getRepo` `subscribeRepos`

### Identity (`com.atproto.identity`)
`resolveHandle`

### Actor (`app.bsky.actor`)
`getPreferences` `putPreferences`

## Testing

```bash
# All tests (210)
cargo test

# Integration tests only
cargo test --test integration

# With output
cargo test -- --nocapture
```

## Federation

To federate with Bluesky, the PDS must be publicly reachable over HTTPS. Use a reverse proxy (nginx, caddy) or a tunnel (ngrok, cloudflare) to expose the server.

DNS setup for handle resolution:
```
_atproto.your-handle.your-domain.com. TXT "did=did:web:your-domain.com"
```

The server automatically serves `/.well-known/did.json` and `/.well-known/atproto-did` for DID and handle verification.

## License

MIT
