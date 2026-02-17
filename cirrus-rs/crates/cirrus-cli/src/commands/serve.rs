//! PDS server command.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use cirrus_pds::blobs::DiskBlobStore;
use cirrus_pds::handle::HandleResolver;
use cirrus_pds::lexicon::LexiconStore;
use cirrus_pds::oauth_storage::OAuthSqliteStorage;
use cirrus_pds::routes::{create_router, AppState};
use cirrus_pds::sequencer::Firehose;
use cirrus_pds::storage::SqliteStorage;

/// Configuration for the PDS server.
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Path to the `SQLite` database.
    pub db_path: String,
    /// JWT secret for session tokens.
    pub jwt_secret: String,
    /// Bcrypt-hashed password for the account.
    pub password_hash: String,
    /// Hostname for this PDS.
    pub hostname: String,
    /// DID of the account.
    pub did: String,
    /// Handle of the account.
    pub handle: String,
    /// Public key in multibase format.
    pub public_key_multibase: String,
    /// Signing key in hex format (for commit signatures).
    pub signing_key_hex: String,
    /// Relay/crawler URLs to notify on new commits.
    pub crawl_relay_urls: Vec<String>,
    /// AppView service URL for proxying read requests (e.g. `https://api.bsky.app`).
    pub appview_url: String,
    /// AppView service DID (e.g. `did:web:api.bsky.app`).
    pub appview_did: String,
}

impl Default for ServerConfig {
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:2583".parse().expect("valid default address"),
            db_path: "pds.db".to_string(),
            jwt_secret: String::new(),
            password_hash: String::new(),
            hostname: "localhost:2583".to_string(),
            did: String::new(),
            handle: String::new(),
            public_key_multibase: String::new(),
            signing_key_hex: String::new(),
            crawl_relay_urls: Vec::new(),
            appview_url: String::new(),
            appview_did: String::new(),
        }
    }
}

/// Validates configuration and emits warnings for missing or inconsistent values.
fn validate_config(config: &ServerConfig) {
    if config.jwt_secret.is_empty() {
        tracing::warn!("PDS_JWT_SECRET is not set — sessions will not work");
    } else if config.jwt_secret.len() < 16 {
        tracing::warn!(
            "PDS_JWT_SECRET is very short (< 16 chars) — consider using a stronger secret"
        );
    }

    if config.did.is_empty() {
        tracing::warn!("PDS_DID is not set — server identity is not configured");
    }

    if config.handle.is_empty() {
        tracing::warn!("PDS_HANDLE is not set — handle resolution will not work");
    }

    if config.hostname == "localhost:2583" {
        tracing::info!("PDS_HOSTNAME is the default (localhost:2583) — set to your public domain for production");
    }

    if config.public_key_multibase.is_empty() && !config.signing_key_hex.is_empty() {
        tracing::warn!(
            "PDS_PUBLIC_KEY is not set but PDS_SIGNING_KEY is — consider deriving the public key"
        );
    }

    if config.signing_key_hex.is_empty() {
        tracing::info!(
            "PDS_SIGNING_KEY is not set — service auth and PLC operations will be unavailable"
        );
    }

    // Verify signing key matches public key if both are provided
    if !config.signing_key_hex.is_empty() && !config.public_key_multibase.is_empty() {
        if let Ok(keypair) = cirrus_common::crypto::Keypair::from_hex(&config.signing_key_hex) {
            let derived = keypair.public_key_multibase();
            if derived != config.public_key_multibase {
                tracing::error!(
                    "PDS_PUBLIC_KEY does not match PDS_SIGNING_KEY! Expected {derived}, got {}",
                    config.public_key_multibase,
                );
            }
        }
    }

    if config.password_hash.is_empty() {
        tracing::info!("PDS_PASSWORD_HASH is not set — use createAccount or set it manually");
    }
}

/// Runs the PDS server.
///
/// # Errors
/// Returns an error if the server fails to start.
pub async fn run(config: ServerConfig) -> Result<()> {
    // Validate configuration
    validate_config(&config);

    // Initialize storage
    let storage = SqliteStorage::open(&config.db_path)?;

    // Initialize blob storage next to the database
    let blob_dir = std::path::Path::new(&config.db_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("blobs");
    let blob_store = DiskBlobStore::new(blob_dir)?;

    // Initialize OAuth storage next to the main database
    let oauth_db_path = std::path::Path::new(&config.db_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("oauth.db");
    let oauth_storage = OAuthSqliteStorage::open(&oauth_db_path.to_string_lossy()).ok();

    // Load signing key if provided
    let signing_key = if config.signing_key_hex.is_empty() {
        None
    } else {
        Some(cirrus_common::crypto::Keypair::from_hex(
            &config.signing_key_hex,
        )?)
    };

    // Create crawler notifier
    let crawlers = if config.crawl_relay_urls.is_empty() {
        None
    } else {
        Some(cirrus_pds::crawlers::Crawlers::new(
            config.hostname.clone(),
            config.crawl_relay_urls,
        ))
    };

    // Create app state
    let state = Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: config.jwt_secret.into_bytes(),
        password_hash: parking_lot::RwLock::new(config.password_hash),
        hostname: config.hostname,
        did: config.did,
        handle: parking_lot::RwLock::new(config.handle),
        public_key_multibase: config.public_key_multibase,
        firehose: Firehose::new(),
        blob_store: Box::new(blob_store),
        handle_resolver: HandleResolver::new(),
        rate_limits: Some(cirrus_pds::rate_limit::RateLimitState::default()),
        oauth_storage,
        signing_key,
        crawlers,
        appview: if config.appview_url.is_empty() {
            None
        } else {
            Some(cirrus_pds::pipethrough::AppViewConfig {
                url: config.appview_url,
                did: config.appview_did,
            })
        },
    });

    // Create router with middleware
    let app = create_router(state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Bind and serve
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!("PDS listening on {}", config.bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
