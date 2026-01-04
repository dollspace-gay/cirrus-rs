//! CBOR encoding and decoding utilities.
//!
//! This module provides helpers for encoding and decoding CBOR data
//! used in the AT Protocol for repository operations.

use bytes::Bytes;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::Error;

/// Encodes a value to CBOR bytes.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| Error::CborEncode(e.to_string()))?;
    Ok(buf)
}

/// Encodes a value to CBOR bytes as `Bytes`.
///
/// # Errors
/// Returns an error if serialization fails.
pub fn encode_bytes<T: Serialize>(value: &T) -> Result<Bytes, Error> {
    encode(value).map(Bytes::from)
}

/// Decodes CBOR bytes to a value.
///
/// # Errors
/// Returns an error if deserialization fails.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::from_reader(bytes)
        .map_err(|e| Error::CborDecode(e.to_string()))
}

/// Decodes CBOR from a reader.
///
/// # Errors
/// Returns an error if deserialization fails.
pub fn decode_reader<T: DeserializeOwned, R: std::io::Read>(reader: R) -> Result<T, Error> {
    ciborium::from_reader(reader)
        .map_err(|e| Error::CborDecode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestRecord {
        text: String,
        count: u32,
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let record = TestRecord {
            text: "hello world".to_string(),
            count: 42,
        };

        let encoded = encode(&record).unwrap();
        let decoded: TestRecord = decode(&encoded).unwrap();

        assert_eq!(record, decoded);
    }

    #[test]
    fn test_encode_bytes() {
        let record = TestRecord {
            text: "test".to_string(),
            count: 1,
        };

        let bytes = encode_bytes(&record).unwrap();
        assert!(!bytes.is_empty());

        let decoded: TestRecord = decode(&bytes).unwrap();
        assert_eq!(record, decoded);
    }

    #[test]
    fn test_decode_invalid() {
        let invalid = &[0xFF, 0xFF, 0xFF];
        let result: Result<TestRecord, _> = decode(invalid);
        assert!(result.is_err());
    }
}
