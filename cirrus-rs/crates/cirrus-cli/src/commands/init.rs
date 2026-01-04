//! PDS initialization command.

use anyhow::Result;
use console::style;
use dialoguer::{Input, Confirm};

/// Runs the interactive PDS initialization wizard.
pub async fn run() -> Result<()> {
    println!("{}", style("Cirrus PDS Setup Wizard").bold().cyan());
    println!();

    // Get domain
    let domain: String = Input::new()
        .with_prompt("Enter your domain (e.g., pds.example.com)")
        .interact_text()?;

    // Get handle
    let handle: String = Input::new()
        .with_prompt("Enter your handle (e.g., alice.example.com)")
        .default(domain.clone())
        .interact_text()?;

    // Generate keys
    let generate_keys = Confirm::new()
        .with_prompt("Generate new signing keys?")
        .default(true)
        .interact()?;

    if generate_keys {
        println!();
        super::secret::generate_key()?;
    }

    // Generate JWT secret
    let generate_jwt = Confirm::new()
        .with_prompt("Generate JWT secret?")
        .default(true)
        .interact()?;

    if generate_jwt {
        println!();
        super::secret::generate_jwt_secret()?;
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

        println!();
        super::secret::hash_password(&password)?;
    }

    println!();
    println!("{}", style("Setup complete!").bold().green());
    println!();
    println!("Next steps:");
    println!("  1. Add the generated secrets to your .dev.vars file");
    println!("  2. Configure your wrangler.toml with:");
    println!("     - DID=did:web:{domain}");
    println!("     - HANDLE={handle}");
    println!("     - PDS_HOSTNAME={domain}");
    println!("  3. Deploy with: npx wrangler deploy");

    Ok(())
}
