//! CID (Content Identifier) utilities.
//!
//! CIDs are self-describing content-addressed identifiers used in the AT Protocol
//! for referencing blocks in the repository.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// Multicodec code for raw bytes.
const RAW_CODEC: u64 = 0x55;

/// Multicodec code for DAG-CBOR.
const DAG_CBOR_CODEC: u64 = 0x71;

/// Multihash code for SHA-256.
const SHA256_CODE: u8 = 0x12;

/// CID version 1.
const CID_VERSION: u8 = 1;

/// A Content Identifier (CID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid {
    /// CID version (always 1 for AT Protocol).
    pub version: u8,
    /// Multicodec code for the content type.
    pub codec: u64,
    /// The multihash bytes.
    pub hash: Vec<u8>,
}

impl Cid {
    /// Creates a CID for DAG-CBOR content.
    #[must_use]
    pub fn for_cbor(data: &[u8]) -> Self {
        Self::new(DAG_CBOR_CODEC, data)
    }

    /// Creates a CID for raw bytes.
    #[must_use]
    pub fn for_raw(data: &[u8]) -> Self {
        Self::new(RAW_CODEC, data)
    }

    /// Creates a new CID with the given codec and data.
    #[must_use]
    pub fn new(codec: u64, data: &[u8]) -> Self {
        let hash = Self::sha256_multihash(data);
        Self {
            version: CID_VERSION,
            codec,
            hash,
        }
    }

    /// Computes SHA-256 multihash for data.
    fn sha256_multihash(data: &[u8]) -> Vec<u8> {
        let digest = Sha256::digest(data);
        let mut multihash = Vec::with_capacity(2 + 32);
        multihash.push(SHA256_CODE); // hash function code
        multihash.push(32); // digest length
        multihash.extend_from_slice(&digest);
        multihash
    }

    /// Encodes the CID to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.extend(Self::encode_varint(self.codec));
        bytes.extend(&self.hash);
        bytes
    }

    /// Encodes the CID to a base32 string (default representation).
    #[must_use]
    pub fn to_string_base32(&self) -> String {
        let bytes = self.to_bytes();
        multibase::encode(multibase::Base::Base32Lower, &bytes)
    }

    /// Encodes the CID to a base58btc string.
    #[must_use]
    pub fn to_string_base58(&self) -> String {
        let bytes = self.to_bytes();
        multibase::encode(multibase::Base::Base58Btc, &bytes)
    }

    /// Parses a CID from a multibase-encoded string.
    ///
    /// # Errors
    /// Returns an error if the CID format is invalid.
    pub fn from_string(s: &str) -> Result<Self, Error> {
        let (_, bytes) = multibase::decode(s)
            .map_err(|e| Error::InvalidCid(format!("multibase decode error: {e}")))?;
        Self::from_bytes(&bytes)
    }

    /// Parses a CID from bytes.
    ///
    /// # Errors
    /// Returns an error if the CID format is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (cid, _) = Self::from_bytes_with_len(bytes)?;
        Ok(cid)
    }

    /// Parses a CID from bytes and returns the number of bytes consumed.
    ///
    /// # Errors
    /// Returns an error if the CID format is invalid.
    pub fn from_bytes_with_len(bytes: &[u8]) -> Result<(Self, usize), Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidCid("empty CID".into()));
        }

        let mut pos = 0;

        // Version
        let version = bytes[pos];
        pos += 1;

        if version != CID_VERSION {
            return Err(Error::InvalidCid(format!(
                "unsupported CID version: {version}"
            )));
        }

        // Codec (varint)
        let (codec, consumed) = Self::decode_varint(&bytes[pos..])
            .ok_or_else(|| Error::InvalidCid("invalid codec varint".into()))?;
        pos += consumed;

        // Multihash: hash code + length + digest
        if bytes.len() < pos + 2 {
            return Err(Error::InvalidCid("multihash too short".into()));
        }

        let hash_code = bytes[pos];
        let hash_len = bytes[pos + 1] as usize;
        let total_hash_len = 2 + hash_len;

        if bytes.len() < pos + total_hash_len {
            return Err(Error::InvalidCid("multihash truncated".into()));
        }

        let hash = bytes[pos..pos + total_hash_len].to_vec();
        pos += total_hash_len;

        Ok((
            Self {
                version,
                codec,
                hash,
            },
            pos,
        ))
    }

    fn encode_varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    fn decode_varint(bytes: &[u8]) -> Option<(u64, usize)> {
        let mut value: u64 = 0;
        let mut shift = 0;
        for (i, &byte) in bytes.iter().enumerate() {
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
        None
    }

    /// Returns true if this is a DAG-CBOR CID.
    #[must_use]
    pub const fn is_dag_cbor(&self) -> bool {
        self.codec == DAG_CBOR_CODEC
    }

    /// Returns true if this is a raw CID.
    #[must_use]
    pub const fn is_raw(&self) -> bool {
        self.codec == RAW_CODEC
    }

    /// Returns the SHA-256 digest bytes (without multihash prefix).
    #[must_use]
    pub fn digest(&self) -> Option<&[u8]> {
        if self.hash.len() >= 2 && self.hash[0] == SHA256_CODE {
            Some(&self.hash[2..])
        } else {
            None
        }
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_base32())
    }
}

impl FromStr for Cid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s)
    }
}

impl Serialize for Cid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as a CBOR tag 42 with bytes (CID link format)
        // For JSON, serialize as string
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string_base32())
        } else {
            // For CBOR, we'd use tag 42 - simplified here as bytes
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Self::from_string(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// Computes SHA-256 hash of data.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

/// Encodes bytes as base64url (no padding).
#[must_use]
pub fn base64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url string to bytes.
///
/// # Errors
/// Returns an error if the input is not valid base64url.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, Error> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(Error::Base64Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cid_for_cbor() {
        let data = b"hello world";
        let cid = Cid::for_cbor(data);

        assert_eq!(cid.version, 1);
        assert!(cid.is_dag_cbor());
        assert!(!cid.is_raw());
    }

    #[test]
    fn test_cid_for_raw() {
        let data = b"raw bytes";
        let cid = Cid::for_raw(data);

        assert!(cid.is_raw());
        assert!(!cid.is_dag_cbor());
    }

    #[test]
    fn test_cid_roundtrip() {
        let data = b"test data for cid";
        let cid = Cid::for_cbor(data);

        let string = cid.to_string_base32();
        let parsed = Cid::from_string(&string).unwrap();

        assert_eq!(cid, parsed);
    }

    #[test]
    fn test_cid_bytes_roundtrip() {
        let data = b"more test data";
        let cid = Cid::for_raw(data);

        let bytes = cid.to_bytes();
        let parsed = Cid::from_bytes(&bytes).unwrap();

        assert_eq!(cid, parsed);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"test data";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_cid_digest() {
        let data = b"test";
        let cid = Cid::for_cbor(data);
        let digest = cid.digest().unwrap();
        assert_eq!(digest.len(), 32);
    }
}
