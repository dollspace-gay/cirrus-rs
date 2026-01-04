//! Secret generation commands.

use anyhow::Result;
use console::style;

/// Generates a new signing key pair.
#[allow(clippy::unnecessary_wraps)]
pub fn generate_key() -> Result<()> {
    let keypair = cirrus_common::crypto::Keypair::generate();

    println!("{}", style("Generated signing key pair:").bold().green());
    println!();
    println!("SIGNING_KEY={}", keypair.private_key_hex());
    println!("SIGNING_KEY_PUBLIC={}", keypair.public_key_multibase());
    println!();
    println!(
        "{}",
        style("Add these to your .dev.vars or wrangler secrets.").dim()
    );

    Ok(())
}

/// Generates a new JWT secret.
#[allow(clippy::unnecessary_wraps)]
pub fn generate_jwt_secret() -> Result<()> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
    let secret = hex::encode(&bytes);

    println!("{}", style("Generated JWT secret:").bold().green());
    println!();
    println!("JWT_SECRET={secret}");
    println!();
    println!(
        "{}",
        style("Add this to your .dev.vars or wrangler secrets.").dim()
    );

    Ok(())
}

/// Hashes a password with bcrypt.
pub fn hash_password(password: &str) -> Result<()> {
    let hash = bcrypt::hash(password, bcrypt::DEFAULT_COST)?;

    println!("{}", style("Generated password hash:").bold().green());
    println!();
    println!("PASSWORD_HASH={hash}");
    println!();
    println!(
        "{}",
        style("Add this to your .dev.vars or wrangler secrets.").dim()
    );

    Ok(())
}
