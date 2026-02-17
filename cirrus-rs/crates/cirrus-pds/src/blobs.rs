//! Blob storage interface.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{PdsError, Result};

/// Maximum blob size (5 MB).
pub const MAX_BLOB_SIZE: usize = 5 * 1024 * 1024;

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

/// Extracts all blob CIDs referenced within a record JSON value.
///
/// Walks the JSON tree looking for objects with `$type: "blob"` and
/// a `ref.$link` field, collecting the CID strings.
#[must_use]
pub fn extract_blob_cids(record: &serde_json::Value) -> Vec<String> {
    let mut cids = Vec::new();
    collect_blob_cids(record, &mut cids);
    cids
}

fn collect_blob_cids(value: &serde_json::Value, cids: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            // Check if this object is a blob reference
            if map.get("$type").and_then(serde_json::Value::as_str) == Some("blob") {
                if let Some(link) = map
                    .get("ref")
                    .and_then(|r| r.get("$link"))
                    .and_then(serde_json::Value::as_str)
                {
                    cids.push(link.to_string());
                }
            }
            // Recurse into all values
            for v in map.values() {
                collect_blob_cids(v, cids);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_blob_cids(v, cids);
            }
        }
        _ => {}
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

/// Disk-backed blob store for production use.
///
/// Stores blobs at `{base_dir}/{cid_prefix}/{cid}` where
/// `cid_prefix` is the first 2 characters of the CID string,
/// providing directory sharding.
pub struct DiskBlobStore {
    base_dir: PathBuf,
}

impl DiskBlobStore {
    /// Creates a new disk blob store at the given directory.
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created.
    pub fn new(base_dir: impl Into<PathBuf>) -> Result<Self> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        Ok(Self { base_dir })
    }

    fn blob_path(&self, cid: &str) -> PathBuf {
        let prefix = &cid[..cid.len().min(2)];
        self.base_dir.join(prefix).join(cid)
    }
}

impl BlobStore for DiskBlobStore {
    fn put_blob(&self, data: &[u8], mime_type: &str) -> Result<BlobRef> {
        if data.len() > MAX_BLOB_SIZE {
            return Err(PdsError::Blob(format!(
                "blob too large: {} bytes (max: {MAX_BLOB_SIZE})",
                data.len()
            )));
        }

        let cid = cirrus_common::cid::Cid::for_raw(data);
        let cid_str = cid.to_string();
        let path = self.blob_path(&cid_str);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&path, data)?;

        Ok(BlobRef::new(&cid_str, mime_type, data.len() as u64))
    }

    fn get_blob(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let path = self.blob_path(cid);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn has_blob(&self, cid: &str) -> Result<bool> {
        Ok(self.blob_path(cid).exists())
    }

    fn delete_blob(&self, cid: &str) -> Result<()> {
        let path = self.blob_path(cid);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
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
    fn test_disk_blob_store_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskBlobStore::new(dir.path().join("blobs")).unwrap();
        let data = b"test blob data for disk store";

        let blob_ref = store.put_blob(data, "text/plain").unwrap();
        let retrieved = store.get_blob(blob_ref.cid()).unwrap();
        assert_eq!(retrieved, Some(data.to_vec()));
    }

    #[test]
    fn test_disk_blob_store_has_and_delete() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskBlobStore::new(dir.path().join("blobs")).unwrap();
        let data = b"delete me";

        let blob_ref = store.put_blob(data, "application/octet-stream").unwrap();
        assert!(store.has_blob(blob_ref.cid()).unwrap());

        store.delete_blob(blob_ref.cid()).unwrap();
        assert!(!store.has_blob(blob_ref.cid()).unwrap());
    }

    #[test]
    fn test_disk_blob_store_get_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskBlobStore::new(dir.path().join("blobs")).unwrap();

        assert_eq!(store.get_blob("bafynonexistent").unwrap(), None);
    }

    #[test]
    fn test_disk_blob_store_delete_nonexistent() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskBlobStore::new(dir.path().join("blobs")).unwrap();

        // Should not error on deleting nonexistent blob
        store.delete_blob("bafynonexistent").unwrap();
    }

    #[test]
    fn test_disk_blob_store_max_size() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskBlobStore::new(dir.path().join("blobs")).unwrap();
        let oversized = vec![0u8; MAX_BLOB_SIZE + 1];

        let result = store.put_blob(&oversized, "application/octet-stream");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_blob_cids_from_record() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "post with image",
            "embed": {
                "$type": "app.bsky.embed.images",
                "images": [
                    {
                        "alt": "test",
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": "bafyimage1" },
                            "mimeType": "image/png",
                            "size": 1024
                        }
                    },
                    {
                        "alt": "test2",
                        "image": {
                            "$type": "blob",
                            "ref": { "$link": "bafyimage2" },
                            "mimeType": "image/jpeg",
                            "size": 2048
                        }
                    }
                ]
            }
        });

        let cids = extract_blob_cids(&record);
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&"bafyimage1".to_string()));
        assert!(cids.contains(&"bafyimage2".to_string()));
    }

    #[test]
    fn test_extract_blob_cids_no_blobs() {
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "just text"
        });

        let cids = extract_blob_cids(&record);
        assert!(cids.is_empty());
    }

    #[test]
    fn test_extract_blob_cids_profile_avatar() {
        let record = serde_json::json!({
            "$type": "app.bsky.actor.profile",
            "displayName": "Test",
            "avatar": {
                "$type": "blob",
                "ref": { "$link": "bafyavatar" },
                "mimeType": "image/png",
                "size": 512
            }
        });

        let cids = extract_blob_cids(&record);
        assert_eq!(cids, vec!["bafyavatar"]);
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
