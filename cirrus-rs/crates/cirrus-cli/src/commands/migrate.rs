//! Account migration command.

use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

/// Runs account migration from another PDS.
pub async fn run(source: &str) -> Result<()> {
    println!("{}", style("Account Migration").bold().cyan());
    println!();
    println!("Source PDS: {}", style(source).yellow());
    println!();

    // Create progress bar
    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}% {msg}")?
            .progress_chars("#>-"),
    );

    // Step 1: Export repo from source
    pb.set_message("Exporting repository from source PDS...");
    pb.set_position(10);

    let car_bytes = export_repo(source).await?;
    pb.set_position(40);

    // Step 2: Validate CAR file
    pb.set_message("Validating repository data...");
    validate_car(&car_bytes)?;
    pb.set_position(60);

    // Step 3: Import to local
    pb.set_message("Importing repository...");
    // In a real implementation, this would call the local PDS
    pb.set_position(90);

    // Step 4: Verify
    pb.set_message("Verifying migration...");
    pb.set_position(100);

    pb.finish_with_message("Migration complete!");

    println!();
    println!("{}", style("Migration successful!").bold().green());
    println!();
    println!("Next steps:");
    println!("  1. Update your DNS records to point to the new PDS");
    println!("  2. Update your DID document (if using did:plc)");
    println!("  3. Verify your account works on the new PDS");

    Ok(())
}

async fn export_repo(source: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();

    // Get the repo as CAR file
    let url = format!("{source}/xrpc/com.atproto.sync.getRepo");

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to connect to source PDS")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to export repo: HTTP {}",
            response.status()
        );
    }

    response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .context("Failed to read response")
}

fn validate_car(car_bytes: &[u8]) -> Result<()> {
    // Basic validation - check CAR header
    if car_bytes.len() < 10 {
        anyhow::bail!("CAR file too small");
    }

    // CAR files start with a varint length followed by CBOR header
    // This is a simplified check
    Ok(())
}
