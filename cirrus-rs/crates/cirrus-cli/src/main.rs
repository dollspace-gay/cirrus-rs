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
    /// Migrate an account from another PDS
    Migrate {
        /// Source PDS URL
        #[arg(long)]
        source: String,
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
        Commands::Migrate { source } => commands::migrate::run(&source).await,
        Commands::Activate => commands::activate::run().await,
        Commands::Deactivate => commands::deactivate::run().await,
        Commands::Secret(secret_cmd) => match secret_cmd {
            SecretCommands::Key => commands::secret::generate_key(),
            SecretCommands::Jwt => commands::secret::generate_jwt_secret(),
            SecretCommands::Password { password } => commands::secret::hash_password(&password),
        },
    }
}
