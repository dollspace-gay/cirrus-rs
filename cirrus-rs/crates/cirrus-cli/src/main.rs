//! Cirrus PDS CLI tools.

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(name = "pds")]
#[command(about = "Cirrus AT Protocol PDS CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new PDS
    Init,
    /// Start the PDS server
    Serve {
        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1:2583")]
        bind: String,
        /// Path to `SQLite` database
        #[arg(long, default_value = "pds.db")]
        db: String,
        /// JWT secret for session tokens
        #[arg(long, env = "PDS_JWT_SECRET", default_value = "")]
        jwt_secret: String,
        /// Bcrypt-hashed password for the account
        #[arg(long, env = "PDS_PASSWORD_HASH", default_value = "")]
        password_hash: String,
        /// DID of the account
        #[arg(long, env = "PDS_DID", default_value = "")]
        did: String,
        /// Handle of the account
        #[arg(long, env = "PDS_HANDLE", default_value = "")]
        handle: String,
        /// Hostname for this PDS
        #[arg(long, env = "PDS_HOSTNAME", default_value = "localhost:2583")]
        hostname: String,
        /// Public key in multibase format
        #[arg(long, env = "PDS_PUBLIC_KEY", default_value = "")]
        public_key: String,
        /// Signing key in hex format (for commit signatures)
        #[arg(long, env = "PDS_SIGNING_KEY", default_value = "")]
        signing_key: String,
        /// Relay/crawler URLs to notify on new commits (comma-separated)
        #[arg(long, env = "PDS_CRAWL_RELAY_URLS", value_delimiter = ',')]
        crawl_relay_urls: Vec<String>,
        /// AppView service URL for proxying read requests
        #[arg(long, env = "PDS_APPVIEW_URL", default_value = "")]
        appview_url: String,
        /// AppView service DID
        #[arg(long, env = "PDS_APPVIEW_DID", default_value = "")]
        appview_did: String,
    },
    /// Migrate an account from another PDS
    Migrate {
        /// Source PDS URL
        #[arg(long)]
        source: String,
        /// Path to local `SQLite` database
        #[arg(long, default_value = "pds.db")]
        db: String,
        /// DID of the account to migrate
        #[arg(long)]
        did: String,
    },
    /// Activate a deactivated account
    Activate,
    /// Deactivate the account
    Deactivate,
    /// Secret generation utilities
    #[command(subcommand)]
    Secret(SecretCommands),
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Generate a new signing key
    Key,
    /// Generate a JWT secret
    Jwt,
    /// Hash a password
    Password {
        /// The password to hash
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file before clap parses args so env vars are available for clap's `env` attribute.
    // Support `--env-file <path>` by pre-scanning argv (must happen before clap parse).
    load_env_file();

    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Serve {
            bind,
            db,
            jwt_secret,
            password_hash,
            did,
            handle,
            hostname,
            public_key,
            signing_key,
            crawl_relay_urls,
            appview_url,
            appview_did,
        } => {
            let config = commands::serve::ServerConfig {
                bind_addr: bind.parse()?,
                db_path: db,
                jwt_secret,
                password_hash,
                did,
                handle,
                hostname,
                public_key_multibase: public_key,
                signing_key_hex: signing_key,
                crawl_relay_urls,
                appview_url,
                appview_did,
            };
            commands::serve::run(config).await
        }
        Commands::Migrate { source, db, did } => commands::migrate::run(&source, &db, &did).await,
        Commands::Activate => commands::activate::run().await,
        Commands::Deactivate => commands::deactivate::run().await,
        Commands::Secret(secret_cmd) => match secret_cmd {
            SecretCommands::Key => commands::secret::generate_key(),
            SecretCommands::Jwt => commands::secret::generate_jwt_secret(),
            SecretCommands::Password { password } => commands::secret::hash_password(&password),
        },
    }
}

/// Loads environment variables from a `.env` file.
///
/// Checks for `--env-file <path>` in argv first; falls back to `.env` in the
/// current directory. Silently ignores missing files.
fn load_env_file() {
    let args: Vec<String> = std::env::args().collect();
    let custom_path = args
        .windows(2)
        .find(|w| w[0] == "--env-file")
        .map(|w| w[1].clone());

    if let Some(path) = custom_path {
        if let Err(e) = dotenvy::from_filename(&path) {
            eprintln!("Warning: failed to load env file {path}: {e}");
        }
    } else {
        let _ = dotenvy::dotenv();
    }
}
