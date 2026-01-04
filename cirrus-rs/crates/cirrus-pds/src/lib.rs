//! AT Protocol Personal Data Server (PDS) implementation.
//!
//! This crate provides the core PDS functionality:
//! - `SQLite` repository storage
//! - XRPC endpoint handlers
//! - WebSocket firehose for federation
//! - Multi-method authentication
//! - Blob storage
//! - DID resolution

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod blobs;
pub mod did;
pub mod error;
pub mod lexicon;
pub mod repo;
pub mod routes;
pub mod sequencer;
pub mod storage;
pub mod xrpc;

pub use error::{PdsError, Result};
