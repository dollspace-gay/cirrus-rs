//! Blob storage interface.

use serde::{Deserialize, Serialize};

use crate::error::Result;

/// A blob reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobRef {
    /// Type marker.
    #[serde(rename = "$type")]
    pub blob_type: String,
    /// Reference to the blob CID.
    #[serde(rename = "ref")]
    pub reference: BlobLink,
    /// MIME type.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Size in bytes.
    pub size: u64,
}

/// A blob link (CID reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobLink {
    /// The CID as a string.
    #[serde(rename = "$link")]
    pub link: String,
}

impl BlobRef {
    /// Creates a new blob reference.
    #[must_use]
    pub fn new(cid: &str, mime_type: &str, size: u64) -> Self {
        Self {
            blob_type: "blob".to_string(),
            reference: BlobLink {
                link: cid.to_string(),
            },
            mime_type: mime_type.to_string(),
            size,
        }
    }

    /// Gets the CID of the blob.
    #[must_use]
    pub fn cid(&self) -> &str {
        &self.reference.link
    }
}

/// Blob storage trait.
pub trait BlobStore: Send + Sync {
    /// Stores a blob and returns its CID.
    ///
    /// # Errors
    /// Returns an error if storage fails.
    fn put_blob(&self, data: &[u8], mime_type: &str) -> Result<BlobRef>;

    /// Retrieves a blob by CID.
    ///
    /// # Errors
    /// Returns an error if retrieval fails.
    fn get_blob(&self, cid: &str) -> Result<Option<Vec<u8>>>;

    /// Checks if a blob exists.
    ///
    /// # Errors
    /// Returns an error if the check fails.
    fn has_blob(&self, cid: &str) -> Result<bool>;

    /// Deletes a blob.
    ///
    /// # Errors
    /// Returns an error if deletion fails.
    fn delete_blob(&self, cid: &str) -> Result<()>;
}

/// In-memory blob store for testing.
#[derive(Default)]
pub struct MemoryBlobStore {
    blobs: parking_lot::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemoryBlobStore {
    /// Creates a new in-memory blob store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlobStore for MemoryBlobStore {
    fn put_blob(&self, data: &[u8], mime_type: &str) -> Result<BlobRef> {
        let cid = cirrus_common::cid::Cid::for_raw(data);
        let cid_str = cid.to_string();

        self.blobs.write().insert(cid_str.clone(), data.to_vec());

        Ok(BlobRef::new(&cid_str, mime_type, data.len() as u64))
    }

    fn get_blob(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.blobs.read().get(cid).cloned())
    }

    fn has_blob(&self, cid: &str) -> Result<bool> {
        Ok(self.blobs.read().contains_key(cid))
    }

    fn delete_blob(&self, cid: &str) -> Result<()> {
        self.blobs.write().remove(cid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_ref() {
        let blob_ref = BlobRef::new("bafytest", "image/png", 1024);

        assert_eq!(blob_ref.blob_type, "blob");
        assert_eq!(blob_ref.cid(), "bafytest");
        assert_eq!(blob_ref.mime_type, "image/png");
        assert_eq!(blob_ref.size, 1024);
    }

    #[test]
    fn test_memory_blob_store() {
        let store = MemoryBlobStore::new();
        let data = b"test blob data";

        // Put blob
        let blob_ref = store.put_blob(data, "application/octet-stream").unwrap();

        // Get blob
        let retrieved = store.get_blob(blob_ref.cid()).unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));

        // Has blob
        assert!(store.has_blob(blob_ref.cid()).unwrap());

        // Delete blob
        store.delete_blob(blob_ref.cid()).unwrap();
        assert!(!store.has_blob(blob_ref.cid()).unwrap());
    }
}
