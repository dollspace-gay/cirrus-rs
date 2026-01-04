//! OAuth 2.1 provider with AT Protocol extensions for Cirrus PDS.
//!
//! This crate implements:
//! - RFC 7636 PKCE (Proof Key for Code Exchange)
//! - RFC 9449 `DPoP` (Demonstrating Proof of Possession)
//! - RFC 9126 PAR (Pushed Authorization Requests)
//! - OAuth 2.1 authorization code flow
//! - AT Protocol extensions for "Login with Bluesky"

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod dpop;
pub mod error;
pub mod par;
pub mod pkce;
pub mod provider;
pub mod storage;
pub mod tokens;

pub use error::{OAuthError, Result};
pub use provider::OAuthProvider;
pub use storage::OAuthStorage;
