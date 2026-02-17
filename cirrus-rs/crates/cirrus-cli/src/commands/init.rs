//! PDS initialization command.

use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use console::style;
use dialoguer::{Confirm, Input};

/// Runs the interactive PDS initialization wizard.
///
/// Collects configuration, generates secrets, and writes a `.env` file.
#[allow(clippy::unused_async)] // Will use async for future network operations
pub async fn run() -> Result<()> {
    println!("{}", style("Cirrus PDS Setup Wizard").bold().cyan());
    println!();

    let mut env_lines = String::new();

    // Get domain
    let domain: String = Input::new()
        .with_prompt("Enter your domain (e.g., pds.example.com)")
        .interact_text()?;

    // Get handle
    let handle: String = Input::new()
        .with_prompt("Enter your handle (e.g., alice.example.com)")
        .default(domain.clone())
        .interact_text()?;

    writeln!(env_lines, "PDS_HOSTNAME={domain}")?;
    writeln!(env_lines, "PDS_HANDLE={handle}")?;
    writeln!(env_lines, "PDS_DID=did:web:{domain}")?;
    writeln!(env_lines)?;

    // Generate keys
    let generate_keys = Confirm::new()
        .with_prompt("Generate new signing keys?")
        .default(true)
        .interact()?;

    if generate_keys {
        let key = super::secret::generate_key_values();
        println!();
        println!("{}", style("Generated signing key pair.").bold().green());
        writeln!(env_lines, "PDS_SIGNING_KEY={}", key.private_key_hex)?;
        writeln!(env_lines, "PDS_PUBLIC_KEY={}", key.public_key_multibase)?;
    }

    // Generate JWT secret
    let generate_jwt = Confirm::new()
        .with_prompt("Generate JWT secret?")
        .default(true)
        .interact()?;

    if generate_jwt {
        let secret = super::secret::generate_jwt_secret_value();
        println!();
        println!("{}", style("Generated JWT secret.").bold().green());
        writeln!(env_lines, "PDS_JWT_SECRET={secret}")?;
    }

    // Set password
    let set_password = Confirm::new()
        .with_prompt("Set account password?")
        .default(true)
        .interact()?;

    if set_password {
        let password: String = dialoguer::Password::new()
            .with_prompt("Enter password")
            .with_confirmation("Confirm password", "Passwords don't match")
            .interact()?;

        let hash = super::secret::hash_password_value(&password)?;
        println!();
        println!("{}", style("Password hashed.").bold().green());
        writeln!(env_lines, "PDS_PASSWORD_HASH={hash}")?;
    }

    // Write .env file
    let env_path = Path::new(".env");
    if env_path.exists() {
        let overwrite = Confirm::new()
            .with_prompt(".env file already exists. Overwrite?")
            .default(false)
            .interact()?;

        if !overwrite {
            println!();
            println!(
                "{}",
                style("Skipped writing .env file. Generated values printed below:").yellow()
            );
            println!();
            print!("{env_lines}");
            return Ok(());
        }
    }

    std::fs::write(env_path, &env_lines)?;

    println!();
    println!("{}", style("Setup complete!").bold().green());
    println!("Configuration written to {}", style(".env").cyan());
    println!();
    println!("Start the server with: {}", style("pds serve").cyan());

    Ok(())
}
