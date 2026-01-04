//! Account deactivation command.

use anyhow::Result;
use console::style;
use dialoguer::Confirm;

/// Deactivates the account.
#[allow(clippy::unused_async)] // Will use async when connecting to PDS
pub async fn run() -> Result<()> {
    println!("{}", style("Account Deactivation").bold().yellow());
    println!();
    println!("This will deactivate your account. While deactivated:");
    println!("  - Your profile will not be visible");
    println!("  - You cannot create new posts");
    println!("  - Your data remains intact");
    println!();

    let confirm = Confirm::new()
        .with_prompt("Are you sure you want to deactivate?")
        .default(false)
        .interact()?;

    if !confirm {
        println!("Cancelled.");
        return Ok(());
    }

    // In a real implementation, this would:
    // 1. Connect to the PDS
    // 2. Call the deactivation endpoint
    // 3. Update the account status

    println!();
    println!("{}", style("Account deactivated.").bold().yellow());
    println!("Run 'pds activate' to reactivate your account.");

    Ok(())
}
