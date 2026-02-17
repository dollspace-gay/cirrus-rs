//! Secret generation commands.

use anyhow::Result;
use console::style;

/// Generated signing key pair.
pub struct GeneratedKey {
    /// Private key in hex.
    pub private_key_hex: String,
    /// Public key in multibase.
    pub public_key_multibase: String,
}

/// Generates a new signing key pair and returns the values.
pub fn generate_key_values() -> GeneratedKey {
    let keypair = cirrus_common::crypto::Keypair::generate();
    GeneratedKey {
        private_key_hex: keypair.private_key_hex(),
        public_key_multibase: keypair.public_key_multibase(),
    }
}

/// Generates a new signing key pair and prints it.
#[allow(clippy::unnecessary_wraps)]
pub fn generate_key() -> Result<()> {
    let key = generate_key_values();

    println!("{}", style("Generated signing key pair:").bold().green());
    println!();
    println!("PDS_SIGNING_KEY={}", key.private_key_hex);
    println!("PDS_PUBLIC_KEY={}", key.public_key_multibase);
    println!();
    println!(
        "{}",
        style("Add these to your .env file or environment variables.").dim()
    );

    Ok(())
}

/// Generates a new JWT secret and returns the hex string.
pub fn generate_jwt_secret_value() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
    hex::encode(bytes)
}

/// Generates a new JWT secret and prints it.
#[allow(clippy::unnecessary_wraps)]
pub fn generate_jwt_secret() -> Result<()> {
    let secret = generate_jwt_secret_value();

    println!("{}", style("Generated JWT secret:").bold().green());
    println!();
    println!("PDS_JWT_SECRET={secret}");
    println!();
    println!(
        "{}",
        style("Add this to your .env file or environment variables.").dim()
    );

    Ok(())
}

/// Hashes a password with bcrypt and returns the hash string.
pub fn hash_password_value(password: &str) -> Result<String> {
    Ok(bcrypt::hash(password, bcrypt::DEFAULT_COST)?)
}

/// Hashes a password with bcrypt and prints it.
pub fn hash_password(password: &str) -> Result<()> {
    let hash = hash_password_value(password)?;

    println!("{}", style("Generated password hash:").bold().green());
    println!();
    println!("PDS_PASSWORD_HASH={hash}");
    println!();
    println!(
        "{}",
        style("Add this to your .env file or environment variables.").dim()
    );

    Ok(())
}
