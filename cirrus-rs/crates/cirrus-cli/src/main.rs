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
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => commands::init::run().await,
        Commands::Serve { bind, db, jwt_secret, password_hash, did, handle, hostname, public_key, signing_key } => {
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
