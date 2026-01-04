//! `SQLite` storage layer for AT Protocol repositories.

use rusqlite::{Connection, params};

use crate::error::Result;

/// Repository storage backed by `SQLite`.
pub struct SqliteStorage {
    conn: Connection,
}

impl SqliteStorage {
    /// Creates a new in-memory storage instance.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates a new storage instance with a file path.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
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
        let mut stmt = self.conn.prepare("SELECT bytes FROM blocks WHERE cid = ?")?;
        let result = stmt.query_row(params![cid], |row| row.get(0));

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
        self.conn.execute(
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
        let mut stmt = self.conn.prepare("SELECT 1 FROM blocks WHERE cid = ?")?;
        let exists = stmt.exists(params![cid])?;
        Ok(exists)
    }

    /// Gets the current repo state.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_repo_state(&self) -> Result<RepoState> {
        let mut stmt = self.conn.prepare(
            "SELECT root_cid, rev, seq, active FROM repo_state WHERE id = 1"
        )?;

        let state = stmt.query_row([], |row| {
            Ok(RepoState {
                root_cid: row.get(0)?,
                rev: row.get(1)?,
                seq: row.get(2)?,
                active: row.get(3)?,
            })
        })?;

        Ok(state)
    }

    /// Updates the repo state.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_repo_state(&self, root_cid: &str, rev: &str) -> Result<i64> {
        self.conn.execute(
            "UPDATE repo_state SET root_cid = ?, rev = ?, seq = seq + 1 WHERE id = 1",
            params![root_cid, rev],
        )?;

        let seq = self.conn.query_row(
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
        let active: i32 = self.conn.query_row(
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
        self.conn.execute(
            "UPDATE repo_state SET active = ? WHERE id = 1",
            params![i32::from(active)],
        )?;
        Ok(())
    }
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
}
