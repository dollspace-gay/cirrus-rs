//! Account migration command.

use std::io::Cursor;

use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressStyle};

use cirrus_common::car::CarReader;
use cirrus_common::Tid;
use cirrus_pds::storage::SqliteStorage;

/// Result of a CAR import operation.
struct ImportResult {
    /// Number of blocks imported.
    block_count: u64,
    /// Root CID of the repository.
    root_cid: String,
}

/// Runs account migration from another PDS.
pub async fn run(source: &str, db_path: &str, did: &str) -> Result<()> {
    println!("{}", style("Account Migration").bold().cyan());
    println!();
    println!("Source PDS: {}", style(source).yellow());
    println!("Target DB:  {}", style(db_path).yellow());
    println!("DID:        {}", style(did).yellow());
    println!();

    let pb = ProgressBar::new(100);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}% {msg}")?
            .progress_chars("#>-"),
    );

    // Step 1: Export repo from source
    pb.set_message("Exporting repository from source PDS...");
    pb.set_position(10);

    let car_bytes = export_repo(source, did).await?;
    pb.set_position(40);

    // Step 2: Validate CAR file
    pb.set_message("Validating repository data...");
    validate_car(&car_bytes)?;
    pb.set_position(60);

    // Step 3: Import to local storage
    pb.set_message("Importing repository...");
    let storage = SqliteStorage::open(db_path)?;
    let result = import_car(&car_bytes, &storage)?;
    pb.set_position(90);

    // Step 4: Verify
    pb.set_message("Verifying migration...");
    let repo_state = storage.get_repo_state()?;
    if repo_state.root_cid.as_deref() != Some(result.root_cid.as_str()) {
        anyhow::bail!("Verification failed: root CID mismatch after import");
    }
    pb.set_position(100);

    pb.finish_with_message("Migration complete!");

    println!();
    println!(
        "{}",
        style(format!(
            "Migration successful! Imported {} blocks.",
            result.block_count
        ))
        .bold()
        .green()
    );
    println!("Root CID: {}", result.root_cid);
    println!();
    println!("Next steps:");
    println!("  1. Update your DNS records to point to the new PDS");
    println!("  2. Update your DID document (if using did:plc)");
    println!("  3. Verify your account works on the new PDS");

    Ok(())
}

async fn export_repo(source: &str, did: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let url = format!("{source}/xrpc/com.atproto.sync.getRepo?did={did}");

    let response = client
        .get(&url)
        .send()
        .await
        .context("Failed to connect to source PDS")?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to export repo: HTTP {}", response.status());
    }

    response
        .bytes()
        .await
        .map(|b| b.to_vec())
        .context("Failed to read response")
}

fn validate_car(car_bytes: &[u8]) -> Result<()> {
    let mut reader =
        CarReader::new(Cursor::new(car_bytes)).context("Failed to parse CAR header")?;

    let header = reader.header();
    if header.version != 1 {
        anyhow::bail!("Unsupported CAR version: {}", header.version);
    }

    if header.roots.is_empty() {
        anyhow::bail!("CAR file has no root CID");
    }

    // Verify at least one block is readable
    if reader.next_block().context("Failed to read first block")?.is_none() {
        anyhow::bail!("CAR file contains no blocks");
    }

    Ok(())
}

fn import_car(car_bytes: &[u8], storage: &SqliteStorage) -> Result<ImportResult> {
    let mut reader =
        CarReader::new(Cursor::new(car_bytes)).context("Failed to parse CAR file")?;

    let root_cid = reader
        .header()
        .roots
        .first()
        .map(|c| c.to_string())
        .ok_or_else(|| anyhow::anyhow!("CAR file has no root CID"))?;

    let mut block_count = 0u64;

    while let Some(block) = reader.next_block().context("Failed to read CAR block")? {
        let cid_str = block.cid.to_string();
        storage
            .put_block(&cid_str, &block.data, None)
            .map_err(|e| anyhow::anyhow!("Failed to store block {cid_str}: {e}"))?;
        block_count += 1;
    }

    // Update repo state with the imported root
    let rev = Tid::now().to_string();
    storage
        .update_repo_state(&root_cid, &rev)
        .map_err(|e| anyhow::anyhow!("Failed to update repo state: {e}"))?;

    Ok(ImportResult {
        block_count,
        root_cid,
    })
}
