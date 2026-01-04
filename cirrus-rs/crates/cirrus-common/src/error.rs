//! Common error types for the Cirrus ecosystem.

use thiserror::Error;

/// Result type alias using the common `Error` type.
pub type Result<T> = std::result::Result<T, Error>;

/// Common errors that can occur across Cirrus crates.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid DID format.
    #[error("invalid DID: {0}")]
    InvalidDid(String),

    /// Invalid handle format.
    #[error("invalid handle: {0}")]
    InvalidHandle(String),

    /// Invalid TID format.
    #[error("invalid TID: {0}")]
    InvalidTid(String),

    /// Invalid AT URI format.
    #[error("invalid AT URI: {0}")]
    InvalidAtUri(String),

    /// Invalid CID format.
    #[error("invalid CID: {0}")]
    InvalidCid(String),

    /// CBOR encoding error.
    #[error("CBOR encoding error: {0}")]
    CborEncode(String),

    /// CBOR decoding error.
    #[error("CBOR decoding error: {0}")]
    CborDecode(String),

    /// Cryptographic operation error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// JWT error.
    #[error("JWT error: {0}")]
    Jwt(String),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
