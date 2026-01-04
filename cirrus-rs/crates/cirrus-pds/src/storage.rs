//! `SQLite` storage layer for AT Protocol repositories.

use parking_lot::Mutex;
use rusqlite::{Connection, params};

use crate::error::Result;

/// Repository storage backed by `SQLite`.
///
/// Uses a `Mutex` to ensure thread-safe access to the connection.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

#[allow(clippy::significant_drop_tightening)]
impl SqliteStorage {
    /// Creates a new in-memory storage instance.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates a new storage instance with a file path.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.lock().execute_batch(
            r"
            -- Block storage (MST nodes + record blocks)
            CREATE TABLE IF NOT EXISTS blocks (
                cid TEXT PRIMARY KEY,
                bytes BLOB NOT NULL,
                rev TEXT
            );

            -- Repo state (single row)
            CREATE TABLE IF NOT EXISTS repo_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                root_cid TEXT,
                rev TEXT,
                seq INTEGER DEFAULT 0,
                active INTEGER DEFAULT 1
            );

            -- Initialize repo state if empty
            INSERT OR IGNORE INTO repo_state (id, seq, active) VALUES (1, 0, 1);

            -- Firehose events (sequenced commit log)
            CREATE TABLE IF NOT EXISTS firehose_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                payload BLOB NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            -- User preferences
            CREATE TABLE IF NOT EXISTS preferences (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data TEXT DEFAULT '[]'
            );

            INSERT OR IGNORE INTO preferences (id) VALUES (1);

            -- Blob reference tracking
            CREATE TABLE IF NOT EXISTS record_blob (
                record_uri TEXT NOT NULL,
                blob_cid TEXT NOT NULL,
                PRIMARY KEY (record_uri, blob_cid)
            );

            -- Imported blobs tracking
            CREATE TABLE IF NOT EXISTS imported_blobs (
                cid TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            -- Indexes
            CREATE INDEX IF NOT EXISTS idx_blocks_rev ON blocks(rev);
            CREATE INDEX IF NOT EXISTS idx_firehose_seq ON firehose_events(seq);
            "
        )?;

        Ok(())
    }

    /// Gets a block by CID.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_block(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        let result = {
            let conn = self.conn.lock();
            let mut stmt = conn.prepare("SELECT bytes FROM blocks WHERE cid = ?")?;
            stmt.query_row(params![cid], |row| row.get(0))
        };

        match result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Puts a block.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn put_block(&self, cid: &str, bytes: &[u8], rev: Option<&str>) -> Result<()> {
        self.conn.lock().execute(
            "INSERT OR REPLACE INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
            params![cid, bytes, rev],
        )?;
        Ok(())
    }

    /// Checks if a block exists.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn has_block(&self, cid: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT 1 FROM blocks WHERE cid = ?")?;
        Ok(stmt.exists(params![cid])?)
    }

    /// Gets the current repo state.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_repo_state(&self) -> Result<RepoState> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT root_cid, rev, seq, active FROM repo_state WHERE id = 1"
        )?;

        Ok(stmt.query_row([], |row| {
            Ok(RepoState {
                root_cid: row.get(0)?,
                rev: row.get(1)?,
                seq: row.get(2)?,
                active: row.get(3)?,
            })
        })?)
    }

    /// Updates the repo state.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_repo_state(&self, root_cid: &str, rev: &str) -> Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE repo_state SET root_cid = ?, rev = ?, seq = seq + 1 WHERE id = 1",
            params![root_cid, rev],
        )?;

        let seq = conn.query_row(
            "SELECT seq FROM repo_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        Ok(seq)
    }

    /// Gets the account active status.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn is_active(&self) -> Result<bool> {
        let conn = self.conn.lock();
        let active: i32 = conn.query_row(
            "SELECT active FROM repo_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        Ok(active != 0)
    }

    /// Sets the account active status.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn set_active(&self, active: bool) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE repo_state SET active = ? WHERE id = 1",
            params![i32::from(active)],
        )?;
        Ok(())
    }

    /// Gets user preferences as a JSON array.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_preferences(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let data: String = conn.query_row(
            "SELECT data FROM preferences WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let prefs: Vec<serde_json::Value> = serde_json::from_str(&data)
            .unwrap_or_default();
        Ok(prefs)
    }

    /// Sets user preferences from a JSON array.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn put_preferences(&self, prefs: &[serde_json::Value]) -> Result<()> {
        let data = serde_json::to_string(prefs)
            .unwrap_or_else(|_| "[]".to_string());
        self.conn.lock().execute(
            "UPDATE preferences SET data = ? WHERE id = 1",
            params![data],
        )?;
        Ok(())
    }

    /// Lists records in a collection with pagination.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_records(
        &self,
        collection: &str,
        limit: u32,
        cursor: Option<&str>,
        reverse: bool,
    ) -> Result<Vec<RecordEntry>> {
        let conn = self.conn.lock();
        let prefix = format!("{collection}:");
        let order = if reverse { "DESC" } else { "ASC" };
        let like_pattern = format!("{prefix}%");

        let raw_rows: Vec<(String, Vec<u8>)> = match cursor {
            Some(c) => {
                let op = if reverse { "<" } else { ">" };
                let query = format!(
                    "SELECT cid, bytes FROM blocks WHERE cid LIKE ?1 AND cid {op} ?2 ORDER BY cid {order} LIMIT ?3"
                );
                let cursor_val = format!("{prefix}{c}");
                conn.prepare(&query)?
                    .query_map(params![like_pattern, cursor_val, limit], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
            }
            None => {
                let query = format!(
                    "SELECT cid, bytes FROM blocks WHERE cid LIKE ?1 ORDER BY cid {order} LIMIT ?2"
                );
                conn.prepare(&query)?
                    .query_map(params![like_pattern, limit], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
            }
        };

        let rows = raw_rows
            .into_iter()
            .map(|(cid, bytes)| {
                let rkey = cid.strip_prefix(&prefix).unwrap_or(&cid).to_string();
                RecordEntry { rkey, bytes }
            })
            .collect();

        Ok(rows)
    }

    /// Deletes a block by CID.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn delete_block(&self, cid: &str) -> Result<bool> {
        let rows = self.conn.lock().execute(
            "DELETE FROM blocks WHERE cid = ?",
            params![cid],
        )?;
        Ok(rows > 0)
    }

    /// Gets all blocks in the repository.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_all_blocks(&self) -> Result<Vec<BlockEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT cid, bytes FROM blocks")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(BlockEntry {
                    cid: row.get(0)?,
                    bytes: row.get(1)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }
}

/// A block entry from storage.
#[derive(Debug, Clone)]
pub struct BlockEntry {
    /// Block CID (storage key).
    pub cid: String,
    /// Block bytes.
    pub bytes: Vec<u8>,
}

/// A record entry from storage.
#[derive(Debug, Clone)]
pub struct RecordEntry {
    /// Record key.
    pub rkey: String,
    /// CBOR-encoded record bytes.
    pub bytes: Vec<u8>,
}

/// Repository state.
#[derive(Debug, Clone)]
pub struct RepoState {
    /// Root CID of the repository.
    pub root_cid: Option<String>,
    /// Current revision.
    pub rev: Option<String>,
    /// Current sequence number.
    pub seq: i64,
    /// Whether the account is active.
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_init() {
        let storage = SqliteStorage::in_memory().unwrap();
        let state = storage.get_repo_state().unwrap();

        assert!(state.root_cid.is_none());
        assert_eq!(state.seq, 0);
        assert!(state.active);
    }

    #[test]
    fn test_block_storage() {
        let storage = SqliteStorage::in_memory().unwrap();

        let cid = "bafytest123";
        let data = b"hello world";

        // Initially not present
        assert!(!storage.has_block(cid).unwrap());
        assert!(storage.get_block(cid).unwrap().is_none());

        // Put block
        storage.put_block(cid, data, None).unwrap();

        // Now present
        assert!(storage.has_block(cid).unwrap());
        assert_eq!(storage.get_block(cid).unwrap(), Some(data.to_vec()));
    }

    #[test]
    fn test_repo_state_update() {
        let storage = SqliteStorage::in_memory().unwrap();

        let seq = storage.update_repo_state("bafyroot", "rev1").unwrap();
        assert_eq!(seq, 1);

        let state = storage.get_repo_state().unwrap();
        assert_eq!(state.root_cid, Some("bafyroot".to_string()));
        assert_eq!(state.rev, Some("rev1".to_string()));
        assert_eq!(state.seq, 1);
    }

    #[test]
    fn test_active_status() {
        let storage = SqliteStorage::in_memory().unwrap();

        assert!(storage.is_active().unwrap());

        storage.set_active(false).unwrap();
        assert!(!storage.is_active().unwrap());

        storage.set_active(true).unwrap();
        assert!(storage.is_active().unwrap());
    }

    #[test]
    fn test_preferences() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Initially empty
        let prefs = storage.get_preferences().unwrap();
        assert!(prefs.is_empty());

        // Set preferences
        let new_prefs = vec![
            serde_json::json!({"$type": "app.bsky.actor.defs#savedFeedsPref", "saved": []}),
            serde_json::json!({"$type": "app.bsky.actor.defs#contentLabelPref", "label": "nsfw", "visibility": "warn"}),
        ];
        storage.put_preferences(&new_prefs).unwrap();

        // Retrieve preferences
        let prefs = storage.get_preferences().unwrap();
        assert_eq!(prefs.len(), 2);
        assert_eq!(prefs[0]["$type"], "app.bsky.actor.defs#savedFeedsPref");
    }

    #[test]
    fn test_list_records() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Add some records
        storage.put_block("app.bsky.feed.post:abc123", b"record1", None).unwrap();
        storage.put_block("app.bsky.feed.post:def456", b"record2", None).unwrap();
        storage.put_block("app.bsky.feed.post:ghi789", b"record3", None).unwrap();
        storage.put_block("app.bsky.feed.like:xyz000", b"like1", None).unwrap();

        // List posts
        let posts = storage.list_records("app.bsky.feed.post", 10, None, false).unwrap();
        assert_eq!(posts.len(), 3);
        assert_eq!(posts[0].rkey, "abc123");
        assert_eq!(posts[1].rkey, "def456");
        assert_eq!(posts[2].rkey, "ghi789");

        // List with limit
        let posts = storage.list_records("app.bsky.feed.post", 2, None, false).unwrap();
        assert_eq!(posts.len(), 2);

        // List with cursor
        let posts = storage.list_records("app.bsky.feed.post", 10, Some("def456"), false).unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].rkey, "ghi789");

        // List in reverse
        let posts = storage.list_records("app.bsky.feed.post", 10, None, true).unwrap();
        assert_eq!(posts.len(), 3);
        assert_eq!(posts[0].rkey, "ghi789");

        // List likes (different collection)
        let likes = storage.list_records("app.bsky.feed.like", 10, None, false).unwrap();
        assert_eq!(likes.len(), 1);
        assert_eq!(likes[0].rkey, "xyz000");
    }

    #[test]
    fn test_delete_block() {
        let storage = SqliteStorage::in_memory().unwrap();

        let cid = "test:record1";
        storage.put_block(cid, b"data", None).unwrap();
        assert!(storage.has_block(cid).unwrap());

        // Delete existing block
        assert!(storage.delete_block(cid).unwrap());
        assert!(!storage.has_block(cid).unwrap());

        // Delete non-existent block returns false
        assert!(!storage.delete_block("nonexistent").unwrap());
    }
}
