//! TID (Timestamp Identifier) type and generation.
//!
//! TIDs are used as record keys in the AT Protocol. They are base32-sortable
//! encoded timestamps with a random component for uniqueness.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// Base32 sort alphabet used for TID encoding.
const BASE32_SORT: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Length of a TID string.
const TID_LENGTH: usize = 13;

/// A validated Timestamp Identifier (TID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tid(String);

impl Tid {
    /// Creates a new TID from a string, validating the format.
    ///
    /// # Errors
    /// Returns an error if the TID format is invalid.
    pub fn new(s: impl Into<String>) -> Result<Self, Error> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Self(s))
    }

    /// Generates a new TID based on the current timestamp.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn now() -> Self {
        Self::from_timestamp(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_micros() as u64) // Safe: won't overflow until year ~586,000
                .unwrap_or(0),
        )
    }

    /// Creates a TID from a microsecond timestamp.
    #[must_use]
    pub fn from_timestamp(timestamp_us: u64) -> Self {
        let clock_id: u16 = rand::random::<u16>() & 0x03FF; // 10-bit random clock ID
        Self::from_timestamp_and_clock(timestamp_us, clock_id)
    }

    /// Creates a TID from a timestamp and clock ID.
    #[must_use]
    pub fn from_timestamp_and_clock(timestamp_us: u64, clock_id: u16) -> Self {
        // TID is 64 bits: 53 bits timestamp + 10 bits clock ID + 1 bit reserved
        let tid_value = (timestamp_us << 10) | u64::from(clock_id & 0x03FF);
        Self(Self::encode_base32_sort(tid_value))
    }

    /// Validates a TID string.
    ///
    /// # Errors
    /// Returns an error if the TID format is invalid.
    pub fn validate(s: &str) -> Result<(), Error> {
        if s.len() != TID_LENGTH {
            return Err(Error::InvalidTid(format!(
                "TID must be {TID_LENGTH} characters, got {}",
                s.len()
            )));
        }

        // Check that all characters are valid base32-sort characters
        for c in s.chars() {
            if !BASE32_SORT.contains(&(c as u8)) {
                return Err(Error::InvalidTid(format!("invalid character: {c}")));
            }
        }

        Ok(())
    }

    fn encode_base32_sort(mut value: u64) -> String {
        let mut result = [0u8; TID_LENGTH];
        for i in (0..TID_LENGTH).rev() {
            result[i] = BASE32_SORT[(value & 0x1F) as usize];
            value >>= 5;
        }
        String::from_utf8(result.to_vec()).unwrap_or_default()
    }

    fn decode_base32_sort(s: &str) -> Option<u64> {
        let mut value: u64 = 0;
        for c in s.chars() {
            let idx = BASE32_SORT.iter().position(|&b| b == c as u8)?;
            value = (value << 5) | (idx as u64);
        }
        Some(value)
    }

    /// Returns the TID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extracts the timestamp in microseconds from the TID.
    #[must_use]
    pub fn timestamp_us(&self) -> Option<u64> {
        Self::decode_base32_sort(&self.0).map(|v| v >> 10)
    }

    /// Extracts the clock ID from the TID.
    #[must_use]
    pub fn clock_id(&self) -> Option<u16> {
        Self::decode_base32_sort(&self.0).map(|v| (v & 0x03FF) as u16)
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Tid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl AsRef<str> for Tid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Default for Tid {
    fn default() -> Self {
        Self::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tid_generation() {
        let tid = Tid::now();
        assert_eq!(tid.as_str().len(), TID_LENGTH);
    }

    #[test]
    fn test_tid_validation() {
        // Valid TID
        assert!(Tid::validate("3jzfcijpj2z2a").is_ok());

        // Invalid: wrong length
        assert!(Tid::validate("abc").is_err());

        // Invalid: wrong characters
        assert!(Tid::validate("0000000000001").is_err()); // 0 and 1 are not in base32-sort
    }

    #[test]
    fn test_tid_from_timestamp() {
        let tid1 = Tid::from_timestamp(1_000_000);
        let tid2 = Tid::from_timestamp(2_000_000);

        // Later timestamp should produce lexicographically greater TID
        assert!(tid2.as_str() > tid1.as_str());
    }

    #[test]
    fn test_tid_timestamp_extraction() {
        let timestamp_us: u64 = 1_704_067_200_000_000; // 2024-01-01 00:00:00 UTC
        let tid = Tid::from_timestamp_and_clock(timestamp_us, 0);

        assert_eq!(tid.timestamp_us(), Some(timestamp_us));
        assert_eq!(tid.clock_id(), Some(0));
    }

    #[test]
    fn test_tid_ordering() {
        let tid1 = Tid::from_timestamp(1_000_000);
        let tid2 = Tid::from_timestamp(2_000_000);

        assert!(tid1 < tid2);
    }

    #[test]
    fn test_tid_from_str() {
        let tid: Tid = "3jzfcijpj2z2a".parse().unwrap();
        assert_eq!(tid.as_str(), "3jzfcijpj2z2a");
    }
}
