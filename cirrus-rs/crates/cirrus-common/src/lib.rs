//! Common types and utilities for Cirrus AT Protocol PDS.
//!
//! This crate provides shared functionality used across the Cirrus ecosystem:
//! - AT Protocol primitives (DID, Handle, TID, `AtUri`)
//! - CBOR encoding/decoding utilities
//! - CID and multiformats handling
//! - Cryptography utilities (Secp256k1, SHA-256)
//! - JWT utilities (ES256K, HS256)
//! - Common error types

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod atproto;
pub mod car;
pub mod cbor;
pub mod cid;
pub mod crypto;
pub mod error;
pub mod jwt;

pub use atproto::{AtUri, Did, Handle, Tid};
pub use error::{Error, Result};
