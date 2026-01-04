//! CAR (Content Addressable aRchive) file format support.
//!
//! CAR files bundle content-addressed blocks for IPFS/IPLD.
//! Format: Header block (DAG-CBOR) + sequence of (varint length, CID, data) blocks.

use std::io::{Read, Write};

use ciborium::Value as CborValue;

use crate::cid::Cid;
use crate::error::{Error, Result};

/// CAR file header.
#[derive(Debug, Clone)]
pub struct CarHeader {
    /// CAR format version (always 1).
    pub version: u64,
    /// Root CIDs of the DAG.
    pub roots: Vec<Cid>,
}

impl CarHeader {
    /// Creates a new CAR header with a single root.
    #[must_use]
    pub fn new(root: Cid) -> Self {
        Self {
            version: 1,
            roots: vec![root],
        }
    }

    /// Encodes the header to DAG-CBOR bytes.
    ///
    /// # Errors
    /// Returns an error if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Build CBOR map: {"roots": [<cids>], "version": 1}
        let roots: Vec<CborValue> = self
            .roots
            .iter()
            .map(|c| {
                // CID as CBOR tag 42 with bytes (including 0x00 multibase prefix)
                let mut cid_bytes = vec![0x00];
                cid_bytes.extend_from_slice(&c.to_bytes());
                CborValue::Tag(42, Box::new(CborValue::Bytes(cid_bytes)))
            })
            .collect();

        let header = CborValue::Map(vec![
            (
                CborValue::Text("roots".to_string()),
                CborValue::Array(roots),
            ),
            (
                CborValue::Text("version".to_string()),
                CborValue::Integer(self.version.into()),
            ),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&header, &mut buf).map_err(|e| Error::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Decodes a header from DAG-CBOR bytes.
    ///
    /// # Errors
    /// Returns an error if decoding fails.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let value: CborValue =
            ciborium::from_reader(data).map_err(|e| Error::CborDecode(e.to_string()))?;

        let map = match value {
            CborValue::Map(m) => m,
            _ => return Err(Error::CborDecode("header must be a map".into())),
        };

        let mut version = 1u64;
        let mut roots = Vec::new();

        for (key, val) in map {
            let key_str = match key {
                CborValue::Text(s) => s,
                _ => continue,
            };

            match key_str.as_str() {
                "version" => {
                    if let CborValue::Integer(i) = val {
                        version = i128::from(i) as u64;
                    }
                }
                "roots" => {
                    if let CborValue::Array(arr) = val {
                        for item in arr {
                            if let CborValue::Tag(42, boxed) = item {
                                if let CborValue::Bytes(bytes) = *boxed {
                                    // Skip the 0x00 multibase prefix if present
                                    let cid_data = if !bytes.is_empty() && bytes[0] == 0x00 {
                                        &bytes[1..]
                                    } else {
                                        &bytes
                                    };
                                    if let Ok(cid) = Cid::from_bytes(cid_data) {
                                        roots.push(cid);
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(Self { version, roots })
    }
}

/// A block in a CAR file.
#[derive(Debug, Clone)]
pub struct CarBlock {
    /// Content identifier.
    pub cid: Cid,
    /// Block data.
    pub data: Vec<u8>,
}

/// Writes a CAR file to a writer.
pub struct CarWriter<W: Write> {
    writer: W,
}

impl<W: Write> CarWriter<W> {
    /// Creates a new CAR writer with the given root CID.
    ///
    /// # Errors
    /// Returns an error if writing the header fails.
    pub fn new(mut writer: W, root: Cid) -> Result<Self> {
        let header = CarHeader::new(root);
        let header_bytes = header.encode()?;

        // Write header length as varint
        write_varint(&mut writer, header_bytes.len() as u64)?;
        writer.write_all(&header_bytes).map_err(Error::Io)?;

        Ok(Self { writer })
    }

    /// Writes a block to the CAR file.
    ///
    /// # Errors
    /// Returns an error if writing fails.
    pub fn write_block(&mut self, cid: &Cid, data: &[u8]) -> Result<()> {
        let cid_bytes = cid.to_bytes();
        let block_len = cid_bytes.len() + data.len();

        write_varint(&mut self.writer, block_len as u64)?;
        self.writer.write_all(&cid_bytes).map_err(Error::Io)?;
        self.writer.write_all(data).map_err(Error::Io)?;

        Ok(())
    }

    /// Finishes writing and returns the inner writer.
    #[must_use]
    pub fn finish(self) -> W {
        self.writer
    }
}

/// Reads blocks from a CAR file.
pub struct CarReader<R: Read> {
    reader: R,
    header: CarHeader,
}

impl<R: Read> CarReader<R> {
    /// Creates a new CAR reader.
    ///
    /// # Errors
    /// Returns an error if reading or parsing the header fails.
    pub fn new(mut reader: R) -> Result<Self> {
        // Read header length
        let header_len = read_varint(&mut reader)?;
        if header_len > 1024 * 1024 {
            return Err(Error::CborDecode("header too large".into()));
        }

        // Read header bytes
        let mut header_bytes = vec![0u8; header_len as usize];
        reader.read_exact(&mut header_bytes).map_err(Error::Io)?;

        let header = CarHeader::decode(&header_bytes)?;

        Ok(Self { reader, header })
    }

    /// Returns the CAR header.
    #[must_use]
    pub fn header(&self) -> &CarHeader {
        &self.header
    }

    /// Reads the next block from the CAR file.
    ///
    /// # Errors
    /// Returns an error if reading or parsing fails.
    pub fn next_block(&mut self) -> Result<Option<CarBlock>> {
        // Try to read block length
        let block_len = match read_varint_optional(&mut self.reader)? {
            Some(len) => len,
            None => return Ok(None),
        };

        if block_len > 2 * 1024 * 1024 {
            return Err(Error::CborDecode("block too large".into()));
        }

        // Read block data
        let mut block_bytes = vec![0u8; block_len as usize];
        self.reader.read_exact(&mut block_bytes).map_err(Error::Io)?;

        // Parse CID from the beginning
        let (cid, cid_len) = Cid::from_bytes_with_len(&block_bytes)?;
        let data = block_bytes[cid_len..].to_vec();

        Ok(Some(CarBlock { cid, data }))
    }
}

// Varint encoding helpers

fn write_varint<W: Write>(writer: &mut W, mut value: u64) -> Result<()> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        writer.write_all(&[byte]).map_err(Error::Io)?;
        if value == 0 {
            break;
        }
    }
    Ok(())
}

fn read_varint<R: Read>(reader: &mut R) -> Result<u64> {
    read_varint_optional(reader)?
        .ok_or_else(|| Error::CborDecode("unexpected EOF reading varint".into()))
}

fn read_varint_optional<R: Read>(reader: &mut R) -> Result<Option<u64>> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut buf = [0u8; 1];

    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                if shift == 0 {
                    return Ok(None);
                }
                return Err(Error::CborDecode("unexpected EOF in varint".into()));
            }
            Ok(_) => {}
            Err(e) => return Err(Error::Io(e)),
        }

        let byte = buf[0];
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(Some(result));
        }
        shift += 7;
        if shift > 63 {
            return Err(Error::CborDecode("varint too large".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_varint_roundtrip() {
        let values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1_000_000];

        for value in values {
            let mut buf = Vec::new();
            write_varint(&mut buf, value).unwrap();

            let mut cursor = Cursor::new(buf);
            let decoded = read_varint(&mut cursor).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn test_car_header_roundtrip() {
        let root = Cid::for_cbor(b"test data");
        let header = CarHeader::new(root.clone());

        let encoded = header.encode().unwrap();
        let decoded = CarHeader::decode(&encoded).unwrap();

        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.roots.len(), 1);
        assert_eq!(decoded.roots[0].to_string(), root.to_string());
    }

    #[test]
    fn test_car_write_read() {
        let data1 = b"block one";
        let data2 = b"block two";
        let cid1 = Cid::for_cbor(data1);
        let cid2 = Cid::for_cbor(data2);

        // Write CAR
        let mut buf = Vec::new();
        let mut writer = CarWriter::new(&mut buf, cid1.clone()).unwrap();
        writer.write_block(&cid1, data1).unwrap();
        writer.write_block(&cid2, data2).unwrap();
        drop(writer);

        // Read CAR
        let mut reader = CarReader::new(Cursor::new(&buf)).unwrap();
        assert_eq!(reader.header().roots.len(), 1);
        assert_eq!(reader.header().roots[0].to_string(), cid1.to_string());

        let block1 = reader.next_block().unwrap().unwrap();
        assert_eq!(block1.cid.to_string(), cid1.to_string());
        assert_eq!(block1.data, data1);

        let block2 = reader.next_block().unwrap().unwrap();
        assert_eq!(block2.cid.to_string(), cid2.to_string());
        assert_eq!(block2.data, data2);

        assert!(reader.next_block().unwrap().is_none());
    }
}
