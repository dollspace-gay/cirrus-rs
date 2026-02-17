//! `SQLite` storage layer for AT Protocol repositories.

use parking_lot::Mutex;
use rusqlite::{params, Connection};

use crate::error::Result;

/// Ordered list of schema migrations.
///
/// Each entry is `(version, sql)`. Migrations are applied in order.
/// Version 1 is the baseline schema — all tables needed for the current codebase.
/// Future schema changes should be added as new entries with incrementing versions.
///
/// **Rules:**
/// - Never modify an existing migration after it has been released.
/// - Always add new migrations at the end with the next version number.
/// - Each migration SQL should be idempotent where possible (use `IF NOT EXISTS`).
const MIGRATIONS: &[(i64, &str)] = &[
    (
        1,
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

        -- Record index (maps collection/rkey to block CID)
        CREATE TABLE IF NOT EXISTS records (
            collection TEXT NOT NULL,
            rkey TEXT NOT NULL,
            block_cid TEXT NOT NULL,
            record_cid TEXT NOT NULL,
            indexed_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (collection, rkey)
        );

        -- MST node blocks (content-addressed, separate from record blocks)
        CREATE TABLE IF NOT EXISTS mst_blocks (
            cid TEXT PRIMARY KEY,
            bytes BLOB NOT NULL
        );

        -- App passwords
        CREATE TABLE IF NOT EXISTS app_passwords (
            name TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            privileged INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        -- Indexes
        CREATE INDEX IF NOT EXISTS idx_blocks_rev ON blocks(rev);
        CREATE INDEX IF NOT EXISTS idx_firehose_seq ON firehose_events(seq);
        CREATE INDEX IF NOT EXISTS idx_records_collection ON records(collection, rkey);
    ",
    ),
    // Migration 2: Key-value settings table for mutable PDS config (e.g. handle).
    (
        2,
        r"
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    ",
    ),
    // Migration 3: Refresh token persistence with rotation and reuse detection.
    (
        3,
        r"
        -- Active refresh tokens with family tracking for rotation
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            did TEXT NOT NULL,
            family_id TEXT NOT NULL,
            next_id TEXT,
            app_password_name TEXT,
            used_at TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_did ON refresh_tokens(did);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
    ",
    ),
    // Migration 4: Email tokens for verification, password reset, and account operations.
    (
        4,
        r"
        CREATE TABLE IF NOT EXISTS email_tokens (
            token TEXT PRIMARY KEY,
            did TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_email_tokens_did ON email_tokens(did);
        CREATE INDEX IF NOT EXISTS idx_email_tokens_expires ON email_tokens(expires_at);
    ",
    ),
    // Migration 5: Invite codes for account creation gating.
    (
        5,
        r"
        CREATE TABLE IF NOT EXISTS invite_codes (
            code TEXT PRIMARY KEY,
            available_uses INTEGER NOT NULL DEFAULT 1,
            disabled INTEGER NOT NULL DEFAULT 0,
            for_account TEXT NOT NULL DEFAULT '',
            created_by TEXT NOT NULL DEFAULT 'admin',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS invite_code_uses (
            code TEXT NOT NULL REFERENCES invite_codes(code),
            used_by TEXT NOT NULL,
            used_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (code, used_by)
        );

        CREATE INDEX IF NOT EXISTS idx_invite_codes_for_account ON invite_codes(for_account);
        CREATE INDEX IF NOT EXISTS idx_invite_code_uses_code ON invite_code_uses(code);
    ",
    ),
    // Migration 6: Account status field for comprehensive state management.
    (
        6,
        r"
        ALTER TABLE repo_state ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
        ALTER TABLE repo_state ADD COLUMN status_changed_at TEXT;
        ALTER TABLE repo_state ADD COLUMN takedown_ref TEXT;
    ",
    ),
    // Migration 7: Multi-user accounts table for hosting multiple accounts on one PDS.
    (
        7,
        r"
        CREATE TABLE IF NOT EXISTS accounts (
            did TEXT PRIMARY KEY,
            handle TEXT NOT NULL UNIQUE,
            email TEXT,
            password_hash TEXT NOT NULL,
            signing_key_hex TEXT,
            recovery_key_hex TEXT,
            invite_code TEXT,
            email_confirmed INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT DEFAULT (datetime('now')),
            deactivated_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_accounts_handle ON accounts(handle);
        CREATE INDEX IF NOT EXISTS idx_accounts_email ON accounts(email);
        CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
    ",
    ),
];

/// Account status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    /// Account is active and operational.
    Active,
    /// Account is deactivated by the user (reversible).
    Deactivated,
    /// Account is suspended by admin/moderation.
    Suspended,
    /// Account has been deleted.
    Deleted,
    /// Account has been taken down by moderation.
    Takendown,
}

impl AccountStatus {
    /// Returns the string representation of the status.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deactivated => "deactivated",
            Self::Suspended => "suspended",
            Self::Deleted => "deleted",
            Self::Takendown => "takendown",
        }
    }

    /// Parses a status from a string.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "deactivated" => Some(Self::Deactivated),
            "suspended" => Some(Self::Suspended),
            "deleted" => Some(Self::Deleted),
            "takendown" => Some(Self::Takendown),
            _ => None,
        }
    }
}

/// A user account entry for multi-user PDS hosting.
#[derive(Debug, Clone)]
pub struct AccountEntry {
    /// The account's DID (primary identifier).
    pub did: String,
    /// The account's handle.
    pub handle: String,
    /// Email address (optional).
    pub email: Option<String>,
    /// Bcrypt-hashed password.
    pub password_hash: String,
    /// Hex-encoded signing key (optional).
    pub signing_key_hex: Option<String>,
    /// Hex-encoded recovery key for `did:plc` (optional).
    pub recovery_key_hex: Option<String>,
    /// Invite code used to create the account (optional).
    pub invite_code: Option<String>,
    /// Whether the email has been confirmed.
    pub email_confirmed: bool,
    /// Account status.
    pub status: AccountStatus,
    /// When the account was created (ISO 8601).
    pub created_at: Option<String>,
    /// When the account was deactivated (ISO 8601, if applicable).
    pub deactivated_at: Option<String>,
}

impl AccountEntry {
    /// Constructs an `AccountEntry` from a SQLite row.
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        let email_confirmed: i32 = row.get(7)?;
        let status_str: String = row.get(8)?;
        Ok(Self {
            did: row.get(0)?,
            handle: row.get(1)?,
            email: row.get(2)?,
            password_hash: row.get(3)?,
            signing_key_hex: row.get(4)?,
            recovery_key_hex: row.get(5)?,
            invite_code: row.get(6)?,
            email_confirmed: email_confirmed != 0,
            status: AccountStatus::from_str(&status_str).unwrap_or(AccountStatus::Active),
            created_at: row.get(9)?,
            deactivated_at: row.get(10)?,
        })
    }
}

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
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Creates a new storage instance with a file path.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Executes a closure within a single SQLite transaction.
    ///
    /// Acquires the connection mutex once, begins a transaction, runs
    /// the closure, and commits on success or rolls back on error.
    /// This ensures atomicity across multiple storage operations.
    ///
    /// # Errors
    /// Returns an error if the transaction fails or the closure returns an error.
    pub fn write_transaction<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.conn.lock();
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match f(&conn) {
            Ok(val) => {
                conn.execute_batch("COMMIT")?;
                Ok(val)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock();
        Self::run_migrations(&conn)
    }

    /// Returns the current schema version, or 0 if no migrations have been applied.
    fn get_schema_version(conn: &Connection) -> i64 {
        // Check if schema_version table exists
        let table_exists: bool = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'")
            .and_then(|mut s| s.exists([]))
            .unwrap_or(false);

        if !table_exists {
            return 0;
        }

        conn.query_row(
            "SELECT version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    }

    /// Sets the schema version.
    fn set_schema_version(conn: &Connection, version: i64) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL,
                updated_at TEXT DEFAULT (datetime('now'))
            )",
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (id, version) VALUES (1, ?)",
            params![version],
        )?;
        Ok(())
    }

    /// Runs all pending migrations in order.
    fn run_migrations(conn: &Connection) -> Result<()> {
        let current_version = Self::get_schema_version(conn);

        for &(version, sql) in MIGRATIONS {
            if version > current_version {
                conn.execute_batch(sql)?;
                Self::set_schema_version(conn, version)?;
            }
        }

        Ok(())
    }

    /// Gets the current schema version.
    ///
    /// Returns the version number of the most recently applied migration.
    #[must_use]
    pub fn schema_version(&self) -> i64 {
        Self::get_schema_version(&self.conn.lock())
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
        Self::put_block_conn(&self.conn.lock(), cid, bytes, rev)
    }

    /// Puts a block using an existing connection (for use inside transactions).
    pub(crate) fn put_block_conn(
        conn: &Connection,
        cid: &str,
        bytes: &[u8],
        rev: Option<&str>,
    ) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO blocks (cid, bytes, rev) VALUES (?, ?, ?)",
            params![cid, bytes, rev],
        )?;
        Ok(())
    }

    /// Gets a block by its content CID (the actual hash-based CID).
    ///
    /// Searches the `records` table for record blocks (mapping content CID
    /// to block key) and the `mst_blocks` table for MST node blocks.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_block_by_content_cid(&self, content_cid: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock();

        // 1. Check records table: content CID → block_cid (key in blocks table) → bytes
        let record_result: rusqlite::Result<String> = conn
            .prepare("SELECT block_cid FROM records WHERE record_cid = ? LIMIT 1")?
            .query_row(params![content_cid], |row| row.get(0));

        if let Ok(block_key) = record_result {
            let block_result: rusqlite::Result<Vec<u8>> = conn
                .prepare("SELECT bytes FROM blocks WHERE cid = ?")?
                .query_row(params![block_key], |row| row.get(0));

            match block_result {
                Ok(bytes) => return Ok(Some(bytes)),
                Err(rusqlite::Error::QueryReturnedNoRows) => {}
                Err(e) => return Err(e.into()),
            }
        }

        // 2. Check mst_blocks table: CID is the actual content CID
        let mst_result: rusqlite::Result<Vec<u8>> = conn
            .prepare("SELECT bytes FROM mst_blocks WHERE cid = ?")?
            .query_row(params![content_cid], |row| row.get(0));

        match mst_result {
            Ok(bytes) => Ok(Some(bytes)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
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
        Self::get_repo_state_conn(&self.conn.lock())
    }

    /// Gets the current repo state using an existing connection.
    pub(crate) fn get_repo_state_conn(conn: &Connection) -> Result<RepoState> {
        let mut stmt = conn.prepare(
            "SELECT root_cid, rev, seq, active, COALESCE(status, 'active') FROM repo_state WHERE id = 1",
        )?;

        Ok(stmt.query_row([], |row| {
            let status_str: String = row.get(4)?;
            Ok(RepoState {
                root_cid: row.get(0)?,
                rev: row.get(1)?,
                seq: row.get(2)?,
                active: row.get(3)?,
                status: AccountStatus::from_str(&status_str).unwrap_or(AccountStatus::Active),
            })
        })?)
    }

    /// Updates the repo state.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_repo_state(&self, root_cid: &str, rev: &str) -> Result<i64> {
        Self::update_repo_state_conn(&self.conn.lock(), root_cid, rev)
    }

    /// Updates the repo state using an existing connection (for transactions).
    pub(crate) fn update_repo_state_conn(
        conn: &Connection,
        root_cid: &str,
        rev: &str,
    ) -> Result<i64> {
        conn.execute(
            "UPDATE repo_state SET root_cid = ?, rev = ?, seq = seq + 1 WHERE id = 1",
            params![root_cid, rev],
        )?;

        let seq = conn.query_row("SELECT seq FROM repo_state WHERE id = 1", [], |row| {
            row.get(0)
        })?;

        Ok(seq)
    }

    /// Gets the account active status.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn is_active(&self) -> Result<bool> {
        let conn = self.conn.lock();
        let active: i32 =
            conn.query_row("SELECT active FROM repo_state WHERE id = 1", [], |row| {
                row.get(0)
            })?;
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

    /// Gets the full account status.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_account_status(&self) -> Result<AccountStatus> {
        let conn = self.conn.lock();
        let status: String = conn
            .query_row("SELECT status FROM repo_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .unwrap_or_else(|_| "active".to_string());
        Ok(AccountStatus::from_str(&status).unwrap_or(AccountStatus::Active))
    }

    /// Sets the full account status with an optional takedown reference.
    ///
    /// Also updates the `active` column for backwards compatibility.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn set_account_status(
        &self,
        status: AccountStatus,
        takedown_ref: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock();
        let active = i32::from(status == AccountStatus::Active);
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE repo_state SET status = ?, active = ?, status_changed_at = ?, takedown_ref = ? WHERE id = 1",
            params![status.as_str(), active, now, takedown_ref],
        )?;
        Ok(())
    }

    /// Gets the takedown reference for the account, if any.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_takedown_ref(&self) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let ref_str: Option<String> = conn
            .query_row(
                "SELECT takedown_ref FROM repo_state WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or(None);
        Ok(ref_str)
    }

    /// Gets user preferences as a JSON array.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_preferences(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.conn.lock();
        let data: String =
            conn.query_row("SELECT data FROM preferences WHERE id = 1", [], |row| {
                row.get(0)
            })?;
        let prefs: Vec<serde_json::Value> = serde_json::from_str(&data).unwrap_or_default();
        Ok(prefs)
    }

    /// Sets user preferences from a JSON array.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn put_preferences(&self, prefs: &[serde_json::Value]) -> Result<()> {
        let data = serde_json::to_string(prefs).unwrap_or_else(|_| "[]".to_string());
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
        Self::delete_block_conn(&self.conn.lock(), cid)
    }

    /// Deletes a block using an existing connection (for transactions).
    pub(crate) fn delete_block_conn(conn: &Connection, cid: &str) -> Result<bool> {
        let rows = conn.execute("DELETE FROM blocks WHERE cid = ?", params![cid])?;
        Ok(rows > 0)
    }

    /// Gets all blocks in the repository.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_all_blocks(&self) -> Result<Vec<BlockEntry>> {
        Self::get_all_blocks_conn(&self.conn.lock())
    }

    /// Gets all blocks using an existing connection (for transactions).
    pub(crate) fn get_all_blocks_conn(conn: &Connection) -> Result<Vec<BlockEntry>> {
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

    /// Indexes a record (upsert into records table).
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn index_record(
        &self,
        collection: &str,
        rkey: &str,
        block_cid: &str,
        record_cid: &str,
    ) -> Result<()> {
        Self::index_record_conn(&self.conn.lock(), collection, rkey, block_cid, record_cid)
    }

    /// Indexes a record using an existing connection (for transactions).
    pub(crate) fn index_record_conn(
        conn: &Connection,
        collection: &str,
        rkey: &str,
        block_cid: &str,
        record_cid: &str,
    ) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO records (collection, rkey, block_cid, record_cid) VALUES (?, ?, ?, ?)",
            params![collection, rkey, block_cid, record_cid],
        )?;
        Ok(())
    }

    /// Removes a record from the index.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn deindex_record(&self, collection: &str, rkey: &str) -> Result<bool> {
        Self::deindex_record_conn(&self.conn.lock(), collection, rkey)
    }

    /// Removes a record from the index using an existing connection.
    pub(crate) fn deindex_record_conn(
        conn: &Connection,
        collection: &str,
        rkey: &str,
    ) -> Result<bool> {
        let rows = conn.execute(
            "DELETE FROM records WHERE collection = ? AND rkey = ?",
            params![collection, rkey],
        )?;
        Ok(rows > 0)
    }

    /// Looks up a record's block CID from the index.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_record_index(&self, collection: &str, rkey: &str) -> Result<Option<RecordIndex>> {
        let conn = self.conn.lock();
        let result = conn
            .prepare("SELECT block_cid, record_cid FROM records WHERE collection = ? AND rkey = ?")
            .and_then(|mut stmt| {
                stmt.query_row(params![collection, rkey], |row| {
                    Ok(RecordIndex {
                        block_cid: row.get(0)?,
                        record_cid: row.get(1)?,
                    })
                })
            });
        match result {
            Ok(idx) => Ok(Some(idx)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Gets records that were written since a given repo revision.
    ///
    /// Returns record data joined from the records index and blocks tables
    /// where the block's rev is greater than the given rev.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_records_since_rev(&self, since_rev: &str) -> Result<Vec<LocalRecordEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT r.collection, r.rkey, r.record_cid, b.bytes, r.indexed_at \
             FROM records r JOIN blocks b ON b.cid = r.block_cid \
             WHERE b.rev > ? ORDER BY b.rev ASC",
        )?;
        let rows = stmt
            .query_map(params![since_rev], |row| {
                Ok(LocalRecordEntry {
                    collection: row.get(0)?,
                    rkey: row.get(1)?,
                    cid: row.get(2)?,
                    bytes: row.get(3)?,
                    indexed_at: row.get(4)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }

    /// Lists records from the index with pagination.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_records_indexed(
        &self,
        collection: &str,
        limit: u32,
        cursor: Option<&str>,
        reverse: bool,
    ) -> Result<Vec<RecordIndexEntry>> {
        let conn = self.conn.lock();
        let order = if reverse { "DESC" } else { "ASC" };

        let rows: Vec<RecordIndexEntry> = match cursor {
            Some(c) => {
                let op = if reverse { "<" } else { ">" };
                let query = format!(
                    "SELECT r.rkey, b.bytes FROM records r JOIN blocks b ON b.cid = r.block_cid \
                     WHERE r.collection = ?1 AND r.rkey {op} ?2 ORDER BY r.rkey {order} LIMIT ?3"
                );
                conn.prepare(&query)?
                    .query_map(params![collection, c, limit], |row| {
                        Ok(RecordIndexEntry {
                            rkey: row.get(0)?,
                            bytes: row.get(1)?,
                        })
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
            }
            None => {
                let query = format!(
                    "SELECT r.rkey, b.bytes FROM records r JOIN blocks b ON b.cid = r.block_cid \
                     WHERE r.collection = ?1 ORDER BY r.rkey {order} LIMIT ?2"
                );
                conn.prepare(&query)?
                    .query_map(params![collection, limit], |row| {
                        Ok(RecordIndexEntry {
                            rkey: row.get(0)?,
                            bytes: row.get(1)?,
                        })
                    })?
                    .filter_map(std::result::Result::ok)
                    .collect()
            }
        };

        Ok(rows)
    }

    /// Replaces all stored MST blocks with a new set (inside a transaction).
    ///
    /// Clears existing MST blocks and inserts the new ones atomically.
    pub(crate) fn store_mst_blocks_conn(
        conn: &Connection,
        blocks: &[(Vec<u8>, cirrus_common::cid::Cid)],
    ) -> Result<()> {
        conn.execute_batch("DELETE FROM mst_blocks")?;
        let mut stmt = conn.prepare("INSERT INTO mst_blocks (cid, bytes) VALUES (?, ?)")?;
        for (bytes, cid) in blocks {
            stmt.execute(params![cid.to_string(), bytes])?;
        }
        Ok(())
    }

    /// Gets all stored MST blocks.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_all_mst_blocks(&self) -> Result<Vec<MstBlockEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT cid, bytes FROM mst_blocks")?;
        let rows = stmt
            .query_map([], |row| {
                Ok(MstBlockEntry {
                    cid: row.get(0)?,
                    bytes: row.get(1)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }

    /// Gets all record entries as lightweight `(path, record_cid)` pairs from the record index.
    ///
    /// Returns entries sorted by path (`collection/rkey`). This is much cheaper than
    /// `get_all_blocks` since it only reads string columns from the index table.
    pub(crate) fn get_all_record_entries_conn(conn: &Connection) -> Result<Vec<(String, String)>> {
        let mut stmt = conn.prepare(
            "SELECT collection || '/' || rkey, record_cid FROM records ORDER BY collection, rkey",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }

    /// Stores blob metadata in the `imported_blobs` table.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn store_blob_metadata(&self, cid: &str, size: usize, mime_type: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO imported_blobs (cid, size, mime_type) VALUES (?, ?, ?)",
            params![cid, size as i64, mime_type],
        )?;
        Ok(())
    }

    /// Lists blob CIDs with pagination.
    ///
    /// Returns up to `limit` CIDs, optionally after `cursor` (exclusive).
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_blob_cids(&self, cursor: Option<&str>, limit: u32) -> Result<Vec<String>> {
        let conn = self.conn.lock();
        if let Some(cursor_cid) = cursor {
            let mut stmt = conn
                .prepare("SELECT cid FROM imported_blobs WHERE cid > ? ORDER BY cid ASC LIMIT ?")?;
            let cids = stmt
                .query_map(params![cursor_cid, limit], |row| row.get(0))?
                .filter_map(std::result::Result::ok)
                .collect();
            Ok(cids)
        } else {
            let mut stmt =
                conn.prepare("SELECT cid FROM imported_blobs ORDER BY cid ASC LIMIT ?")?;
            let cids = stmt
                .query_map(params![limit], |row| row.get(0))?
                .filter_map(std::result::Result::ok)
                .collect();
            Ok(cids)
        }
    }

    /// Associates a blob CID with a record URI in the `record_blob` table.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn associate_blob(&self, record_uri: &str, blob_cid: &str) -> Result<()> {
        Self::associate_blob_conn(&self.conn.lock(), record_uri, blob_cid)
    }

    /// Associates a blob CID with a record URI using an existing connection.
    pub(crate) fn associate_blob_conn(
        conn: &Connection,
        record_uri: &str,
        blob_cid: &str,
    ) -> Result<()> {
        conn.execute(
            "INSERT OR IGNORE INTO record_blob (record_uri, blob_cid) VALUES (?, ?)",
            params![record_uri, blob_cid],
        )?;
        Ok(())
    }

    /// Removes all blob associations for a record URI.
    ///
    /// Returns the list of blob CIDs that were disassociated.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub(crate) fn disassociate_record_blobs_conn(
        conn: &Connection,
        record_uri: &str,
    ) -> Result<Vec<String>> {
        let mut stmt = conn.prepare("SELECT blob_cid FROM record_blob WHERE record_uri = ?")?;
        let cids: Vec<String> = stmt
            .query_map(params![record_uri], |row| row.get(0))?
            .filter_map(std::result::Result::ok)
            .collect();

        conn.execute(
            "DELETE FROM record_blob WHERE record_uri = ?",
            params![record_uri],
        )?;
        Ok(cids)
    }

    /// Lists all blob references (record_uri, blob_cid) from the `record_blob` table.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_blob_references(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare("SELECT record_uri, blob_cid FROM record_blob")?;
        let refs = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(refs)
    }

    /// Finds blob CIDs that have no remaining references in `record_blob`.
    ///
    /// Given a list of candidate CIDs, returns those with zero references.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub(crate) fn find_unreferenced_blobs_conn(
        conn: &Connection,
        candidate_cids: &[String],
    ) -> Result<Vec<String>> {
        let mut unreferenced = Vec::new();
        for cid in candidate_cids {
            let count: i64 = conn
                .prepare("SELECT COUNT(*) FROM record_blob WHERE blob_cid = ?")?
                .query_row(params![cid], |row| row.get(0))?;
            if count == 0 {
                unreferenced.push(cid.clone());
            }
        }
        Ok(unreferenced)
    }

    /// Deletes blob metadata from `imported_blobs` for the given CIDs.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub(crate) fn delete_blob_metadata_conn(conn: &Connection, cids: &[String]) -> Result<()> {
        for cid in cids {
            conn.execute("DELETE FROM imported_blobs WHERE cid = ?", params![cid])?;
        }
        Ok(())
    }

    /// Gets a setting value by key.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock();
        let result = conn
            .prepare("SELECT value FROM settings WHERE key = ?")?
            .query_row(params![key], |row| row.get(0));
        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Sets a setting value (upsert).
    ///
    /// # Errors
    /// Returns an error if the upsert fails.
    pub fn put_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Creates an app password entry.
    ///
    /// Stores the bcrypt hash of the password (not the plaintext).
    ///
    /// # Errors
    /// Returns an error if the insert fails (e.g. duplicate name).
    pub fn create_app_password(
        &self,
        name: &str,
        password_hash: &str,
        privileged: bool,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO app_passwords (name, password_hash, privileged) VALUES (?, ?, ?)",
            params![name, password_hash, i32::from(privileged)],
        )?;
        Ok(())
    }

    /// Lists all app passwords (returns name, privileged, created_at — never the hash).
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_app_passwords(&self) -> Result<Vec<AppPasswordEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT name, privileged, created_at FROM app_passwords ORDER BY created_at DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(AppPasswordEntry {
                    name: row.get(0)?,
                    privileged: row.get::<_, i32>(1)? != 0,
                    created_at: row.get(2)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }

    /// Deletes an app password by name.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn delete_app_password(&self, name: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM app_passwords WHERE name = ?", params![name])?;
        Ok(rows > 0)
    }

    /// Tries to verify a password against all stored app passwords.
    ///
    /// Returns the matching app password entry if one matches.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn verify_app_password(&self, password: &str) -> Result<Option<AppPasswordEntry>> {
        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare("SELECT name, password_hash, privileged, created_at FROM app_passwords")?;
        let rows: Vec<(String, String, i32, String)> = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        for (name, hash, privileged, created_at) in rows {
            if bcrypt::verify(password, &hash).unwrap_or(false) {
                return Ok(Some(AppPasswordEntry {
                    name,
                    privileged: privileged != 0,
                    created_at,
                }));
            }
        }
        Ok(None)
    }

    /// Persists a firehose event to the database.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn persist_event(&self, event_type: &str, payload: &[u8]) -> Result<i64> {
        Self::persist_event_conn(&self.conn.lock(), event_type, payload)
    }

    /// Persists a firehose event using an existing connection (for transactions).
    pub(crate) fn persist_event_conn(
        conn: &Connection,
        event_type: &str,
        payload: &[u8],
    ) -> Result<i64> {
        conn.execute(
            "INSERT INTO firehose_events (event_type, payload) VALUES (?, ?)",
            params![event_type, payload],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Retrieves firehose events from a given cursor (exclusive).
    ///
    /// Returns up to `limit` events with `seq > cursor`.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_events_after(&self, cursor: i64, limit: u32) -> Result<Vec<StoredEvent>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT seq, event_type, payload FROM firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT ?"
        )?;
        let rows = stmt
            .query_map(params![cursor, limit], |row| {
                Ok(StoredEvent {
                    seq: row.get(0)?,
                    event_type: row.get(1)?,
                    payload: row.get(2)?,
                })
            })?
            .filter_map(std::result::Result::ok)
            .collect();
        Ok(rows)
    }

    /// Gets the latest sequence number from persisted events.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_latest_event_seq(&self) -> Result<Option<i64>> {
        let conn = self.conn.lock();
        let result: std::result::Result<i64, _> =
            conn.query_row("SELECT MAX(seq) FROM firehose_events", [], |row| row.get(0));
        match result {
            Ok(seq) => Ok(Some(seq)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
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

/// An MST block entry from storage.
#[derive(Debug, Clone)]
pub struct MstBlockEntry {
    /// Content-addressed CID of the MST node.
    pub cid: String,
    /// DAG-CBOR encoded MST node bytes.
    pub bytes: Vec<u8>,
}

/// A record index lookup result.
#[derive(Debug, Clone)]
pub struct RecordIndex {
    /// Block CID (storage key for the block).
    pub block_cid: String,
    /// Content-addressed CID of the record.
    pub record_cid: String,
}

/// A record entry from the index with its data.
#[derive(Debug, Clone)]
pub struct RecordIndexEntry {
    /// Record key.
    pub rkey: String,
    /// CBOR-encoded record bytes.
    pub bytes: Vec<u8>,
}

/// A record entry returned by `get_records_since_rev`.
#[derive(Debug, Clone)]
pub struct LocalRecordEntry {
    /// Collection NSID.
    pub collection: String,
    /// Record key.
    pub rkey: String,
    /// Content-addressed CID of the record.
    pub cid: String,
    /// CBOR-encoded record bytes.
    pub bytes: Vec<u8>,
    /// When the record was indexed.
    pub indexed_at: String,
}

/// An app password entry (without the hash).
#[derive(Debug, Clone)]
pub struct AppPasswordEntry {
    /// User-assigned name for the app password.
    pub name: String,
    /// Whether this password grants privileged access.
    pub privileged: bool,
    /// When the app password was created (ISO 8601).
    pub created_at: String,
}

/// A persisted firehose event from storage.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    /// Sequence number.
    pub seq: i64,
    /// Event type (e.g. "commit", "identity", "account").
    pub event_type: String,
    /// Encoded event payload.
    pub payload: Vec<u8>,
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
    /// Account status (active, deactivated, suspended, deleted, takendown).
    pub status: AccountStatus,
}

/// An invite code with metadata and usage info.
#[derive(Debug, Clone)]
pub struct InviteCodeEntry {
    /// The invite code string.
    pub code: String,
    /// Number of times this code can be used.
    pub available_uses: i64,
    /// Whether this code has been disabled.
    pub disabled: bool,
    /// Account this code is assigned to (empty for admin-created codes).
    pub for_account: String,
    /// Who created this code.
    pub created_by: String,
    /// When the code was created (ISO 8601).
    pub created_at: String,
    /// List of accounts that used this code.
    pub uses: Vec<InviteCodeUse>,
    /// Total number of times this code has been used.
    pub use_count: i64,
}

/// A record of an invite code being used.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InviteCodeUse {
    /// DID of the account that used the code.
    #[serde(rename = "usedBy")]
    pub used_by: String,
    /// When the code was used (ISO 8601).
    #[serde(rename = "usedAt")]
    pub used_at: String,
}

/// Valid email token purposes.
pub const EMAIL_TOKEN_PURPOSES: &[&str] = &[
    "confirm_email",
    "update_email",
    "reset_password",
    "delete_account",
    "plc_operation",
];

/// Email token expiry in seconds (15 minutes).
const EMAIL_TOKEN_EXPIRY_SECS: i64 = 900;

/// A stored email token.
#[derive(Debug, Clone)]
pub struct EmailToken {
    /// Unique token value.
    pub token: String,
    /// DID of the token owner.
    pub did: String,
    /// Token purpose (e.g. `reset_password`).
    pub purpose: String,
    /// When the token expires (ISO 8601).
    pub expires_at: String,
}

impl SqliteStorage {
    /// Creates an email token for the given purpose.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn create_email_token(&self, did: &str, purpose: &str) -> Result<String> {
        let token = crate::auth::generate_token_id();
        let expires_at =
            (chrono::Utc::now() + chrono::Duration::seconds(EMAIL_TOKEN_EXPIRY_SECS)).to_rfc3339();

        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO email_tokens (token, did, purpose, expires_at) VALUES (?, ?, ?, ?)",
            params![token, did, purpose, expires_at],
        )?;
        Ok(token)
    }

    /// Validates and consumes an email token.
    ///
    /// Returns the token data if valid (not expired), then deletes it.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn consume_email_token(
        &self,
        token: &str,
        expected_purpose: &str,
    ) -> Result<Option<EmailToken>> {
        let conn = self.conn.lock();
        let result = conn.prepare(
            "SELECT token, did, purpose, expires_at FROM email_tokens WHERE token = ? AND purpose = ?"
        )?.query_row(params![token, expected_purpose], |row| {
            Ok(EmailToken {
                token: row.get(0)?,
                did: row.get(1)?,
                purpose: row.get(2)?,
                expires_at: row.get(3)?,
            })
        });

        match result {
            Ok(email_token) => {
                // Check expiration
                let expired = chrono::DateTime::parse_from_rfc3339(&email_token.expires_at)
                    .map(|exp| chrono::Utc::now() > exp)
                    .unwrap_or(true);

                // Delete the token (consumed or expired)
                let _ = conn.execute("DELETE FROM email_tokens WHERE token = ?", params![token]);

                if expired {
                    Ok(None)
                } else {
                    Ok(Some(email_token))
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Cleans up expired email tokens.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn cleanup_expired_email_tokens(&self) -> Result<usize> {
        let conn = self.conn.lock();
        let count = conn.execute(
            "DELETE FROM email_tokens WHERE expires_at < datetime('now')",
            [],
        )?;
        Ok(count)
    }

    /// Wipes all account data from storage.
    ///
    /// Deletes all rows from every user-data table. The schema/tables remain.
    ///
    /// # Errors
    /// Returns an error if any DELETE statement fails.
    pub fn wipe_account_data(&self) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "DELETE FROM blocks;
             DELETE FROM repo_state;
             DELETE FROM firehose_events;
             DELETE FROM preferences;
             DELETE FROM record_blob;
             DELETE FROM imported_blobs;
             DELETE FROM records;
             DELETE FROM mst_blocks;
             DELETE FROM app_passwords;
             DELETE FROM settings;
             DELETE FROM refresh_tokens;
             DELETE FROM email_tokens;",
        )?;
        Ok(())
    }
}

/// A persisted refresh token.
#[derive(Debug, Clone)]
pub struct RefreshTokenRow {
    /// Unique token ID (opaque string embedded in the JWT).
    pub id: String,
    /// DID of the token owner.
    pub did: String,
    /// Family ID for rotation tracking (shared across rotations).
    pub family_id: String,
    /// ID of the next token in the family (set on rotation).
    pub next_id: Option<String>,
    /// App password name if token was created via app password.
    pub app_password_name: Option<String>,
    /// When the token was used for rotation (ISO 8601).
    pub used_at: Option<String>,
    /// When the token expires (ISO 8601).
    pub expires_at: String,
    /// When the token was created (ISO 8601).
    pub created_at: String,
}

/// Grace period for refresh token rotation (2 hours in seconds).
const REFRESH_GRACE_PERIOD_SECS: i64 = 7200;

impl SqliteStorage {
    /// Stores a new refresh token.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn store_refresh_token(
        &self,
        id: &str,
        did: &str,
        family_id: &str,
        app_password_name: Option<&str>,
        expires_at: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO refresh_tokens (id, did, family_id, app_password_name, expires_at) VALUES (?, ?, ?, ?, ?)",
            params![id, did, family_id, app_password_name, expires_at],
        )?;
        Ok(())
    }

    /// Gets a refresh token by ID.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_refresh_token(&self, id: &str) -> Result<Option<RefreshTokenRow>> {
        let conn = self.conn.lock();
        let result = conn.prepare(
            "SELECT id, did, family_id, next_id, app_password_name, used_at, expires_at, created_at FROM refresh_tokens WHERE id = ?"
        )?.query_row(params![id], |row| {
            Ok(RefreshTokenRow {
                id: row.get(0)?,
                did: row.get(1)?,
                family_id: row.get(2)?,
                next_id: row.get(3)?,
                app_password_name: row.get(4)?,
                used_at: row.get(5)?,
                expires_at: row.get(6)?,
                created_at: row.get(7)?,
            })
        });
        match result {
            Ok(token) => Ok(Some(token)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Marks a refresh token as used and sets its successor.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn use_refresh_token(&self, id: &str, next_id: &str) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "UPDATE refresh_tokens SET used_at = datetime('now'), next_id = ? WHERE id = ?",
            params![next_id, id],
        )?;
        Ok(())
    }

    /// Revokes all refresh tokens in a family (reuse detection).
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn revoke_token_family(&self, family_id: &str) -> Result<usize> {
        let conn = self.conn.lock();
        let count = conn.execute(
            "DELETE FROM refresh_tokens WHERE family_id = ?",
            params![family_id],
        )?;
        Ok(count)
    }

    /// Revokes all refresh tokens for a DID.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn revoke_all_refresh_tokens(&self, did: &str) -> Result<usize> {
        let conn = self.conn.lock();
        let count = conn.execute("DELETE FROM refresh_tokens WHERE did = ?", params![did])?;
        Ok(count)
    }

    /// Cleans up expired refresh tokens.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn cleanup_expired_refresh_tokens(&self) -> Result<usize> {
        let conn = self.conn.lock();
        let count = conn.execute(
            "DELETE FROM refresh_tokens WHERE expires_at < datetime('now')",
            [],
        )?;
        Ok(count)
    }

    // ── Invite code operations ──────────────────────────────────────────

    /// Creates a new invite code.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn create_invite_code(
        &self,
        code: &str,
        available_uses: i64,
        for_account: &str,
        created_by: &str,
    ) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO invite_codes (code, available_uses, for_account, created_by) VALUES (?, ?, ?, ?)",
            params![code, available_uses, for_account, created_by],
        )?;
        Ok(())
    }

    /// Gets an invite code with its current use count.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_invite_code(&self, code: &str) -> Result<Option<InviteCodeEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT c.code, c.available_uses, c.disabled, c.for_account, c.created_by, c.created_at,
                    COUNT(u.used_by) as use_count
             FROM invite_codes c
             LEFT JOIN invite_code_uses u ON c.code = u.code
             WHERE c.code = ?
             GROUP BY c.code",
        )?;
        let entry = stmt
            .query_row(params![code], |row| {
                Ok(InviteCodeEntry {
                    code: row.get(0)?,
                    available_uses: row.get(1)?,
                    disabled: row.get::<_, i32>(2)? != 0,
                    for_account: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at: row.get(5)?,
                    uses: Vec::new(),
                    use_count: row.get(6)?,
                })
            })
            .ok();
        Ok(entry)
    }

    /// Uses an invite code (records who used it). Returns `false` if the code
    /// is invalid, disabled, or has no remaining uses.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn use_invite_code(&self, code: &str, used_by: &str) -> Result<bool> {
        let conn = self.conn.lock();

        // Check the code exists, is not disabled, and has remaining uses
        let valid: bool = conn
            .prepare(
                "SELECT 1 FROM invite_codes c
                 WHERE c.code = ? AND c.disabled = 0
                 AND (SELECT COUNT(*) FROM invite_code_uses WHERE code = c.code) < c.available_uses",
            )?
            .exists(params![code])?;

        if !valid {
            return Ok(false);
        }

        conn.execute(
            "INSERT OR IGNORE INTO invite_code_uses (code, used_by) VALUES (?, ?)",
            params![code, used_by],
        )?;
        Ok(true)
    }

    /// Lists invite codes for a specific account, or all codes if `for_account` is empty.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_invite_codes(&self, for_account: &str) -> Result<Vec<InviteCodeEntry>> {
        let conn = self.conn.lock();
        let query = if for_account.is_empty() {
            "SELECT c.code, c.available_uses, c.disabled, c.for_account, c.created_by, c.created_at,
                    COUNT(u.used_by) as use_count
             FROM invite_codes c
             LEFT JOIN invite_code_uses u ON c.code = u.code
             GROUP BY c.code
             ORDER BY c.created_at DESC"
        } else {
            "SELECT c.code, c.available_uses, c.disabled, c.for_account, c.created_by, c.created_at,
                    COUNT(u.used_by) as use_count
             FROM invite_codes c
             LEFT JOIN invite_code_uses u ON c.code = u.code
             WHERE c.for_account = ?
             GROUP BY c.code
             ORDER BY c.created_at DESC"
        };

        let mut stmt = conn.prepare(query)?;
        let row_mapper = |row: &rusqlite::Row| {
            Ok(InviteCodeEntry {
                code: row.get(0)?,
                available_uses: row.get(1)?,
                disabled: row.get::<_, i32>(2)? != 0,
                for_account: row.get(3)?,
                created_by: row.get(4)?,
                created_at: row.get(5)?,
                uses: Vec::new(),
                use_count: row.get(6)?,
            })
        };

        let mut entries: Vec<InviteCodeEntry> = if for_account.is_empty() {
            stmt.query_map([], row_mapper)?
                .filter_map(std::result::Result::ok)
                .collect()
        } else {
            stmt.query_map(params![for_account], row_mapper)?
                .filter_map(std::result::Result::ok)
                .collect()
        };
        drop(stmt);

        // Populate uses for each code
        for entry in &mut entries {
            let mut use_stmt = conn.prepare(
                "SELECT used_by, used_at FROM invite_code_uses WHERE code = ? ORDER BY used_at",
            )?;
            entry.uses = use_stmt
                .query_map(params![entry.code], |row| {
                    Ok(InviteCodeUse {
                        used_by: row.get(0)?,
                        used_at: row.get(1)?,
                    })
                })?
                .filter_map(std::result::Result::ok)
                .collect();
        }

        Ok(entries)
    }

    /// Disables an invite code.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn disable_invite_code(&self, code: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE invite_codes SET disabled = 1 WHERE code = ?",
            params![code],
        )?;
        Ok(rows > 0)
    }

    // ── Multi-user account management ──────────────────────────────────

    /// Creates a new account entry.
    ///
    /// # Errors
    /// Returns an error if the DID or handle already exists.
    pub fn create_account_entry(&self, entry: &AccountEntry) -> Result<()> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO accounts (did, handle, email, password_hash, signing_key_hex, recovery_key_hex, invite_code, email_confirmed, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                entry.did,
                entry.handle,
                entry.email,
                entry.password_hash,
                entry.signing_key_hex,
                entry.recovery_key_hex,
                entry.invite_code,
                i32::from(entry.email_confirmed),
                entry.status.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Looks up an account by DID.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_account_by_did(&self, did: &str) -> Result<Option<AccountEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT did, handle, email, password_hash, signing_key_hex, recovery_key_hex, invite_code, email_confirmed, status, created_at, deactivated_at FROM accounts WHERE did = ?",
        )?;

        let result = stmt.query_row(params![did], AccountEntry::from_row);
        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Looks up an account by handle.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_account_by_handle(&self, handle: &str) -> Result<Option<AccountEntry>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT did, handle, email, password_hash, signing_key_hex, recovery_key_hex, invite_code, email_confirmed, status, created_at, deactivated_at FROM accounts WHERE handle = ?",
        )?;

        let result = stmt.query_row(params![handle], AccountEntry::from_row);
        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Looks up an account by DID or handle.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_account_by_identifier(&self, identifier: &str) -> Result<Option<AccountEntry>> {
        if identifier.starts_with("did:") {
            self.get_account_by_did(identifier)
        } else {
            self.get_account_by_handle(identifier)
        }
    }

    /// Returns the total number of accounts.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_account_count(&self) -> Result<i64> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM accounts", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Lists all accounts, optionally filtered by status.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn list_accounts(
        &self,
        status_filter: Option<AccountStatus>,
        limit: i64,
        cursor: Option<&str>,
    ) -> Result<Vec<AccountEntry>> {
        let conn = self.conn.lock();

        let cols = "did, handle, email, password_hash, signing_key_hex, recovery_key_hex, invite_code, email_confirmed, status, created_at, deactivated_at";

        let rows: Vec<AccountEntry> = match (&status_filter, cursor) {
            (Some(s), Some(c)) => {
                let q = format!(
                    "SELECT {cols} FROM accounts WHERE status = ? AND did > ? ORDER BY did LIMIT ?"
                );
                let mut stmt = conn.prepare(&q)?;
                let v: Vec<AccountEntry> = stmt
                    .query_map(params![s.as_str(), c, limit], AccountEntry::from_row)?
                    .filter_map(std::result::Result::ok)
                    .collect();
                v
            }
            (Some(s), None) => {
                let q =
                    format!("SELECT {cols} FROM accounts WHERE status = ? ORDER BY did LIMIT ?");
                let mut stmt = conn.prepare(&q)?;
                let v: Vec<AccountEntry> = stmt
                    .query_map(params![s.as_str(), limit], AccountEntry::from_row)?
                    .filter_map(std::result::Result::ok)
                    .collect();
                v
            }
            (None, Some(c)) => {
                let q = format!("SELECT {cols} FROM accounts WHERE did > ? ORDER BY did LIMIT ?");
                let mut stmt = conn.prepare(&q)?;
                let v: Vec<AccountEntry> = stmt
                    .query_map(params![c, limit], AccountEntry::from_row)?
                    .filter_map(std::result::Result::ok)
                    .collect();
                v
            }
            (None, None) => {
                let q = format!("SELECT {cols} FROM accounts ORDER BY did LIMIT ?");
                let mut stmt = conn.prepare(&q)?;
                let v: Vec<AccountEntry> = stmt
                    .query_map(params![limit], AccountEntry::from_row)?
                    .filter_map(std::result::Result::ok)
                    .collect();
                v
            }
        };

        Ok(rows)
    }

    /// Updates an account's handle.
    ///
    /// # Errors
    /// Returns an error if the DID doesn't exist or the handle is taken.
    pub fn update_account_handle_entry(&self, did: &str, new_handle: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE accounts SET handle = ? WHERE did = ?",
            params![new_handle, did],
        )?;
        Ok(rows > 0)
    }

    /// Updates an account's password hash.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_account_password(&self, did: &str, new_password_hash: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE accounts SET password_hash = ? WHERE did = ?",
            params![new_password_hash, did],
        )?;
        Ok(rows > 0)
    }

    /// Updates an account's email.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_account_email(&self, did: &str, email: &str, confirmed: bool) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE accounts SET email = ?, email_confirmed = ? WHERE did = ?",
            params![email, i32::from(confirmed), did],
        )?;
        Ok(rows > 0)
    }

    /// Sets the email_confirmed flag for an account.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn confirm_account_email(&self, did: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute(
            "UPDATE accounts SET email_confirmed = 1 WHERE did = ?",
            params![did],
        )?;
        Ok(rows > 0)
    }

    /// Updates an account's status.
    ///
    /// # Errors
    /// Returns an error if the update fails.
    pub fn update_account_status(&self, did: &str, status: AccountStatus) -> Result<bool> {
        let conn = self.conn.lock();
        let deactivated_at = if status == AccountStatus::Deactivated {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };
        let rows = conn.execute(
            "UPDATE accounts SET status = ?, deactivated_at = ? WHERE did = ?",
            params![status.as_str(), deactivated_at, did],
        )?;
        Ok(rows > 0)
    }

    /// Deletes an account entry.
    ///
    /// # Errors
    /// Returns an error if the delete fails.
    pub fn delete_account_entry(&self, did: &str) -> Result<bool> {
        let conn = self.conn.lock();
        let rows = conn.execute("DELETE FROM accounts WHERE did = ?", params![did])?;
        Ok(rows > 0)
    }

    /// Checks if a used token is within the grace period.
    /// Used tokens can still be valid for a grace period after rotation.
    #[must_use]
    pub fn is_within_grace_period(used_at: &str) -> bool {
        let Ok(used) = chrono::DateTime::parse_from_rfc3339(used_at) else {
            // Also try SQLite's datetime format
            let Ok(naive) = chrono::NaiveDateTime::parse_from_str(used_at, "%Y-%m-%d %H:%M:%S")
            else {
                return false;
            };
            let used_utc = naive.and_utc();
            let now = chrono::Utc::now();
            return (now - used_utc).num_seconds() < REFRESH_GRACE_PERIOD_SECS;
        };
        let now = chrono::Utc::now();
        (now - used.to_utc()).num_seconds() < REFRESH_GRACE_PERIOD_SECS
    }
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
        storage
            .put_block("app.bsky.feed.post:abc123", b"record1", None)
            .unwrap();
        storage
            .put_block("app.bsky.feed.post:def456", b"record2", None)
            .unwrap();
        storage
            .put_block("app.bsky.feed.post:ghi789", b"record3", None)
            .unwrap();
        storage
            .put_block("app.bsky.feed.like:xyz000", b"like1", None)
            .unwrap();

        // List posts
        let posts = storage
            .list_records("app.bsky.feed.post", 10, None, false)
            .unwrap();
        assert_eq!(posts.len(), 3);
        assert_eq!(posts[0].rkey, "abc123");
        assert_eq!(posts[1].rkey, "def456");
        assert_eq!(posts[2].rkey, "ghi789");

        // List with limit
        let posts = storage
            .list_records("app.bsky.feed.post", 2, None, false)
            .unwrap();
        assert_eq!(posts.len(), 2);

        // List with cursor
        let posts = storage
            .list_records("app.bsky.feed.post", 10, Some("def456"), false)
            .unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].rkey, "ghi789");

        // List in reverse
        let posts = storage
            .list_records("app.bsky.feed.post", 10, None, true)
            .unwrap();
        assert_eq!(posts.len(), 3);
        assert_eq!(posts[0].rkey, "ghi789");

        // List likes (different collection)
        let likes = storage
            .list_records("app.bsky.feed.like", 10, None, false)
            .unwrap();
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

    #[test]
    fn test_write_transaction_commits() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .write_transaction(|conn| {
                SqliteStorage::put_block_conn(conn, "tx:block1", b"data1", None)?;
                SqliteStorage::put_block_conn(conn, "tx:block2", b"data2", None)?;
                SqliteStorage::update_repo_state_conn(conn, "bafyroot", "rev1")?;
                Ok(())
            })
            .unwrap();

        // Both blocks visible after commit
        assert!(storage.has_block("tx:block1").unwrap());
        assert!(storage.has_block("tx:block2").unwrap());
        let state = storage.get_repo_state().unwrap();
        assert_eq!(state.root_cid, Some("bafyroot".to_string()));
    }

    #[test]
    fn test_write_transaction_rolls_back() {
        let storage = SqliteStorage::in_memory().unwrap();

        let result: Result<()> = storage.write_transaction(|conn| {
            SqliteStorage::put_block_conn(conn, "tx:block1", b"data", None)?;
            // Simulate failure after first write
            Err(crate::error::PdsError::InvalidRecord(
                "test rollback".into(),
            ))
        });

        assert!(result.is_err());
        // Block should NOT be visible after rollback
        assert!(!storage.has_block("tx:block1").unwrap());
    }

    #[test]
    fn test_persist_and_retrieve_events() {
        let storage = SqliteStorage::in_memory().unwrap();

        let seq1 = storage.persist_event("commit", b"payload1").unwrap();
        let seq2 = storage.persist_event("commit", b"payload2").unwrap();
        let seq3 = storage.persist_event("identity", b"payload3").unwrap();

        assert!(seq2 > seq1);
        assert!(seq3 > seq2);

        // Retrieve all from start
        let events = storage.get_events_after(0, 10).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "commit");
        assert_eq!(events[0].payload, b"payload1");
        assert_eq!(events[2].event_type, "identity");

        // Retrieve after cursor
        let events = storage.get_events_after(seq1, 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].seq, seq2);

        // Latest seq
        let latest = storage.get_latest_event_seq().unwrap();
        assert_eq!(latest, Some(seq3));
    }

    #[test]
    fn test_persist_event_in_transaction() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .write_transaction(|conn| {
                SqliteStorage::put_block_conn(conn, "tx:rec", b"data", None)?;
                SqliteStorage::persist_event_conn(conn, "commit", b"event-payload")?;
                Ok(())
            })
            .unwrap();

        let events = storage.get_events_after(0, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload, b"event-payload");
    }

    #[test]
    fn test_record_index_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Store a block
        storage
            .put_block("app.bsky.feed.post:abc", b"cbor-data", None)
            .unwrap();

        // Index it
        storage
            .index_record(
                "app.bsky.feed.post",
                "abc",
                "app.bsky.feed.post:abc",
                "bafycid1",
            )
            .unwrap();

        // Lookup
        let idx = storage
            .get_record_index("app.bsky.feed.post", "abc")
            .unwrap()
            .unwrap();
        assert_eq!(idx.block_cid, "app.bsky.feed.post:abc");
        assert_eq!(idx.record_cid, "bafycid1");

        // Not found
        assert!(storage
            .get_record_index("app.bsky.feed.post", "nonexistent")
            .unwrap()
            .is_none());

        // Deindex
        assert!(storage.deindex_record("app.bsky.feed.post", "abc").unwrap());
        assert!(storage
            .get_record_index("app.bsky.feed.post", "abc")
            .unwrap()
            .is_none());

        // Deindex non-existent returns false
        assert!(!storage.deindex_record("app.bsky.feed.post", "abc").unwrap());
    }

    #[test]
    fn test_record_index_list() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Store blocks and index them
        for i in 0..5 {
            let rkey = format!("rec{i:04}");
            let block_cid = format!("app.bsky.feed.post:{rkey}");
            let record_cid = format!("bafycid{i}");
            storage
                .put_block(&block_cid, format!("data{i}").as_bytes(), None)
                .unwrap();
            storage
                .index_record("app.bsky.feed.post", &rkey, &block_cid, &record_cid)
                .unwrap();
        }

        // Also add a like
        storage
            .put_block("app.bsky.feed.like:like1", b"likedata", None)
            .unwrap();
        storage
            .index_record(
                "app.bsky.feed.like",
                "like1",
                "app.bsky.feed.like:like1",
                "bafylike",
            )
            .unwrap();

        // List posts
        let posts = storage
            .list_records_indexed("app.bsky.feed.post", 10, None, false)
            .unwrap();
        assert_eq!(posts.len(), 5);
        assert_eq!(posts[0].rkey, "rec0000");
        assert_eq!(posts[4].rkey, "rec0004");

        // List with limit
        let posts = storage
            .list_records_indexed("app.bsky.feed.post", 2, None, false)
            .unwrap();
        assert_eq!(posts.len(), 2);

        // List with cursor
        let posts = storage
            .list_records_indexed("app.bsky.feed.post", 10, Some("rec0002"), false)
            .unwrap();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].rkey, "rec0003");

        // List in reverse
        let posts = storage
            .list_records_indexed("app.bsky.feed.post", 10, None, true)
            .unwrap();
        assert_eq!(posts[0].rkey, "rec0004");

        // List likes (separate collection)
        let likes = storage
            .list_records_indexed("app.bsky.feed.like", 10, None, false)
            .unwrap();
        assert_eq!(likes.len(), 1);
    }

    #[test]
    fn test_get_records_since_rev() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Store records at different revs
        storage
            .put_block("app.bsky.feed.post:tid1", b"post1-data", Some("rev001"))
            .unwrap();
        storage
            .index_record(
                "app.bsky.feed.post",
                "tid1",
                "app.bsky.feed.post:tid1",
                "bafypost1",
            )
            .unwrap();

        storage
            .put_block("app.bsky.feed.post:tid2", b"post2-data", Some("rev002"))
            .unwrap();
        storage
            .index_record(
                "app.bsky.feed.post",
                "tid2",
                "app.bsky.feed.post:tid2",
                "bafypost2",
            )
            .unwrap();

        storage
            .put_block(
                "app.bsky.actor.profile:self",
                b"profile-data",
                Some("rev003"),
            )
            .unwrap();
        storage
            .index_record(
                "app.bsky.actor.profile",
                "self",
                "app.bsky.actor.profile:self",
                "bafyprofile",
            )
            .unwrap();

        // Since rev000: should get all 3
        let entries = storage.get_records_since_rev("rev000").unwrap();
        assert_eq!(entries.len(), 3);

        // Since rev001: should get 2 (rev002 and rev003)
        let entries = storage.get_records_since_rev("rev001").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].collection, "app.bsky.feed.post");
        assert_eq!(entries[0].rkey, "tid2");
        assert_eq!(entries[1].collection, "app.bsky.actor.profile");

        // Since rev003: should get none
        let entries = storage.get_records_since_rev("rev003").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_blob_reference_tracking() {
        let storage = SqliteStorage::in_memory().unwrap();

        let uri1 = "at://did:plc:test/app.bsky.feed.post/tid1";
        let uri2 = "at://did:plc:test/app.bsky.feed.post/tid2";

        // Associate blobs with records
        storage.associate_blob(uri1, "bafyblob1").unwrap();
        storage.associate_blob(uri1, "bafyblob2").unwrap();
        storage.associate_blob(uri2, "bafyblob1").unwrap(); // shared blob

        // Disassociate uri1's blobs
        let disassociated = storage
            .write_transaction(|conn| SqliteStorage::disassociate_record_blobs_conn(conn, uri1))
            .unwrap();
        assert_eq!(disassociated.len(), 2);
        assert!(disassociated.contains(&"bafyblob1".to_string()));
        assert!(disassociated.contains(&"bafyblob2".to_string()));

        // bafyblob1 is still referenced by uri2, bafyblob2 is unreferenced
        let unreferenced = storage
            .write_transaction(|conn| {
                SqliteStorage::find_unreferenced_blobs_conn(conn, &disassociated)
            })
            .unwrap();
        assert_eq!(unreferenced, vec!["bafyblob2"]);

        // Delete unreferenced blob metadata
        storage
            .store_blob_metadata("bafyblob2", 100, "image/png")
            .unwrap();
        storage
            .write_transaction(|conn| SqliteStorage::delete_blob_metadata_conn(conn, &unreferenced))
            .unwrap();

        // Verify it was cleaned up
        let cids = storage.list_blob_cids(None, 10).unwrap();
        assert!(!cids.contains(&"bafyblob2".to_string()));
    }

    #[test]
    fn test_mst_block_storage() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Initially no MST blocks
        let blocks = storage.get_all_mst_blocks().unwrap();
        assert!(blocks.is_empty());

        // Store some MST blocks inside a transaction
        let cid1 = cirrus_common::cid::Cid::for_cbor(b"mst-node-1");
        let cid2 = cirrus_common::cid::Cid::for_cbor(b"mst-node-2");
        let mst_blocks = vec![
            (b"mst-node-1".to_vec(), cid1.clone()),
            (b"mst-node-2".to_vec(), cid2.clone()),
        ];

        storage
            .write_transaction(|conn| SqliteStorage::store_mst_blocks_conn(conn, &mst_blocks))
            .unwrap();

        // Retrieve stored blocks
        let blocks = storage.get_all_mst_blocks().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].bytes, b"mst-node-1");
        assert_eq!(blocks[1].bytes, b"mst-node-2");

        // Replacing clears old blocks
        let cid3 = cirrus_common::cid::Cid::for_cbor(b"mst-node-3");
        let new_blocks = vec![(b"mst-node-3".to_vec(), cid3.clone())];
        storage
            .write_transaction(|conn| SqliteStorage::store_mst_blocks_conn(conn, &new_blocks))
            .unwrap();

        let blocks = storage.get_all_mst_blocks().unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].bytes, b"mst-node-3");
    }

    #[test]
    fn test_get_all_record_entries() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Index some records
        storage
            .index_record(
                "app.bsky.feed.like",
                "like1",
                "app.bsky.feed.like:like1",
                "bafylike1",
            )
            .unwrap();
        storage
            .index_record(
                "app.bsky.feed.post",
                "abc",
                "app.bsky.feed.post:abc",
                "bafypost1",
            )
            .unwrap();
        storage
            .index_record(
                "app.bsky.feed.post",
                "def",
                "app.bsky.feed.post:def",
                "bafypost2",
            )
            .unwrap();

        // Get all entries (should be sorted by collection/rkey)
        let entries = storage
            .write_transaction(|conn| SqliteStorage::get_all_record_entries_conn(conn))
            .unwrap();

        assert_eq!(entries.len(), 3);
        // Sorted: like comes before post
        assert_eq!(entries[0].0, "app.bsky.feed.like/like1");
        assert_eq!(entries[0].1, "bafylike1");
        assert_eq!(entries[1].0, "app.bsky.feed.post/abc");
        assert_eq!(entries[1].1, "bafypost1");
        assert_eq!(entries[2].0, "app.bsky.feed.post/def");
        assert_eq!(entries[2].1, "bafypost2");
    }

    #[test]
    fn test_app_password_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Initially empty
        let passwords = storage.list_app_passwords().unwrap();
        assert!(passwords.is_empty());

        // Create app passwords
        let hash1 = crate::auth::hash_password("test-app-pw-1").unwrap();
        let hash2 = crate::auth::hash_password("test-app-pw-2").unwrap();
        storage
            .create_app_password("My App", &hash1, false)
            .unwrap();
        storage
            .create_app_password("Privileged App", &hash2, true)
            .unwrap();

        // List
        let passwords = storage.list_app_passwords().unwrap();
        assert_eq!(passwords.len(), 2);
        // Ordered by created_at DESC (both created at same second, but insertion order)
        let names: Vec<&str> = passwords.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"My App"));
        assert!(names.contains(&"Privileged App"));

        // Verify privileged flag
        let priv_entry = passwords
            .iter()
            .find(|p| p.name == "Privileged App")
            .unwrap();
        assert!(priv_entry.privileged);
        let std_entry = passwords.iter().find(|p| p.name == "My App").unwrap();
        assert!(!std_entry.privileged);

        // Delete
        assert!(storage.delete_app_password("My App").unwrap());
        assert!(!storage.delete_app_password("Nonexistent").unwrap());
        let passwords = storage.list_app_passwords().unwrap();
        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0].name, "Privileged App");
    }

    #[test]
    fn test_app_password_verify() {
        let storage = SqliteStorage::in_memory().unwrap();

        let password = "abcd-efgh-ijkl-mnop";
        let hash = crate::auth::hash_password(password).unwrap();
        storage
            .create_app_password("Test App", &hash, false)
            .unwrap();

        // Correct password
        let result = storage.verify_app_password(password).unwrap();
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.name, "Test App");
        assert!(!entry.privileged);

        // Wrong password
        let result = storage.verify_app_password("wrong-pass-word-here").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_app_password_duplicate_name() {
        let storage = SqliteStorage::in_memory().unwrap();

        let hash = crate::auth::hash_password("pw1").unwrap();
        storage.create_app_password("Dup", &hash, false).unwrap();

        // Duplicate name should fail (PRIMARY KEY constraint)
        let hash2 = crate::auth::hash_password("pw2").unwrap();
        let result = storage.create_app_password("Dup", &hash2, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_settings_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Initially no value
        assert!(storage.get_setting("handle").unwrap().is_none());

        // Set a value
        storage.put_setting("handle", "alice.example.com").unwrap();
        assert_eq!(
            storage.get_setting("handle").unwrap(),
            Some("alice.example.com".to_string())
        );

        // Update the value (upsert)
        storage.put_setting("handle", "bob.example.com").unwrap();
        assert_eq!(
            storage.get_setting("handle").unwrap(),
            Some("bob.example.com".to_string())
        );

        // Different keys are independent
        storage.put_setting("other_key", "other_value").unwrap();
        assert_eq!(
            storage.get_setting("other_key").unwrap(),
            Some("other_value".to_string())
        );
        assert_eq!(
            storage.get_setting("handle").unwrap(),
            Some("bob.example.com".to_string())
        );
    }

    #[test]
    fn test_schema_version_tracking() {
        let storage = SqliteStorage::in_memory().unwrap();

        // After init, schema version should be the latest migration version
        let version = storage.schema_version();
        assert_eq!(version, MIGRATIONS.last().unwrap().0);
    }

    #[test]
    fn test_migrations_are_idempotent() {
        // Running init_schema twice should not fail
        let storage = SqliteStorage::in_memory().unwrap();
        let v1 = storage.schema_version();

        // Re-run migrations — should be a no-op
        storage.init_schema().unwrap();
        let v2 = storage.schema_version();

        assert_eq!(v1, v2);
    }

    #[test]
    fn test_incremental_migration() {
        // Simulate a database at version 0 (pre-migration era) and verify
        // that running migrations brings it to the current version.
        let conn = Connection::open_in_memory().unwrap();

        // No schema_version table yet
        let version = SqliteStorage::get_schema_version(&conn);
        assert_eq!(version, 0);

        // Run migrations
        SqliteStorage::run_migrations(&conn).unwrap();
        let version = SqliteStorage::get_schema_version(&conn);
        assert_eq!(version, MIGRATIONS.last().unwrap().0);

        // Verify tables exist by querying them
        conn.execute_batch("SELECT COUNT(*) FROM blocks").unwrap();
        conn.execute_batch("SELECT COUNT(*) FROM repo_state")
            .unwrap();
        conn.execute_batch("SELECT COUNT(*) FROM app_passwords")
            .unwrap();
        conn.execute_batch("SELECT COUNT(*) FROM schema_version")
            .unwrap();
        conn.execute_batch("SELECT COUNT(*) FROM refresh_tokens")
            .unwrap();
    }

    #[test]
    fn test_refresh_token_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Store a token
        storage
            .store_refresh_token("tok1", "did:plc:test", "fam1", None, "2099-01-01T00:00:00Z")
            .unwrap();

        // Retrieve it
        let token = storage.get_refresh_token("tok1").unwrap().unwrap();
        assert_eq!(token.id, "tok1");
        assert_eq!(token.did, "did:plc:test");
        assert_eq!(token.family_id, "fam1");
        assert!(token.next_id.is_none());
        assert!(token.used_at.is_none());

        // Non-existent token returns None
        assert!(storage.get_refresh_token("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_refresh_token_rotation() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .store_refresh_token("tok1", "did:plc:test", "fam1", None, "2099-01-01T00:00:00Z")
            .unwrap();

        // Use token (rotate to tok2)
        storage.use_refresh_token("tok1", "tok2").unwrap();

        let token = storage.get_refresh_token("tok1").unwrap().unwrap();
        assert_eq!(token.next_id.as_deref(), Some("tok2"));
        assert!(token.used_at.is_some());
    }

    #[test]
    fn test_revoke_token_family() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Create a family of tokens
        storage
            .store_refresh_token("tok1", "did:plc:test", "fam1", None, "2099-01-01T00:00:00Z")
            .unwrap();
        storage
            .store_refresh_token("tok2", "did:plc:test", "fam1", None, "2099-01-01T00:00:00Z")
            .unwrap();
        storage
            .store_refresh_token("tok3", "did:plc:test", "fam2", None, "2099-01-01T00:00:00Z")
            .unwrap();

        // Revoke family 1
        let count = storage.revoke_token_family("fam1").unwrap();
        assert_eq!(count, 2);

        // Family 1 tokens gone
        assert!(storage.get_refresh_token("tok1").unwrap().is_none());
        assert!(storage.get_refresh_token("tok2").unwrap().is_none());

        // Family 2 untouched
        assert!(storage.get_refresh_token("tok3").unwrap().is_some());
    }

    #[test]
    fn test_revoke_all_refresh_tokens() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .store_refresh_token(
                "tok1",
                "did:plc:user1",
                "fam1",
                None,
                "2099-01-01T00:00:00Z",
            )
            .unwrap();
        storage
            .store_refresh_token(
                "tok2",
                "did:plc:user1",
                "fam2",
                None,
                "2099-01-01T00:00:00Z",
            )
            .unwrap();
        storage
            .store_refresh_token(
                "tok3",
                "did:plc:user2",
                "fam3",
                None,
                "2099-01-01T00:00:00Z",
            )
            .unwrap();

        let count = storage.revoke_all_refresh_tokens("did:plc:user1").unwrap();
        assert_eq!(count, 2);

        assert!(storage.get_refresh_token("tok1").unwrap().is_none());
        assert!(storage.get_refresh_token("tok2").unwrap().is_none());
        assert!(storage.get_refresh_token("tok3").unwrap().is_some());
    }

    #[test]
    fn test_refresh_token_with_app_password() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .store_refresh_token(
                "tok1",
                "did:plc:test",
                "fam1",
                Some("my-app"),
                "2099-01-01T00:00:00Z",
            )
            .unwrap();

        let token = storage.get_refresh_token("tok1").unwrap().unwrap();
        assert_eq!(token.app_password_name.as_deref(), Some("my-app"));
    }

    #[test]
    fn test_grace_period() {
        // Recent timestamp should be within grace period
        let now = chrono::Utc::now().to_rfc3339();
        assert!(SqliteStorage::is_within_grace_period(&now));

        // Old timestamp should be outside grace period
        let old = (chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339();
        assert!(!SqliteStorage::is_within_grace_period(&old));
    }

    #[test]
    fn test_email_token_create_and_consume() {
        let storage = SqliteStorage::in_memory().unwrap();
        let token = storage
            .create_email_token("did:plc:test", "confirm_email")
            .unwrap();
        assert!(!token.is_empty());

        // Consume it
        let result = storage
            .consume_email_token(&token, "confirm_email")
            .unwrap();
        assert!(result.is_some());
        let email_token = result.unwrap();
        assert_eq!(email_token.did, "did:plc:test");
        assert_eq!(email_token.purpose, "confirm_email");

        // Should not be consumable again (single-use)
        let result2 = storage
            .consume_email_token(&token, "confirm_email")
            .unwrap();
        assert!(result2.is_none());
    }

    #[test]
    fn test_email_token_wrong_purpose() {
        let storage = SqliteStorage::in_memory().unwrap();
        let token = storage
            .create_email_token("did:plc:test", "confirm_email")
            .unwrap();

        // Consuming with wrong purpose should fail
        let result = storage
            .consume_email_token(&token, "reset_password")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_email_token_nonexistent() {
        let storage = SqliteStorage::in_memory().unwrap();
        let result = storage
            .consume_email_token("nonexistent", "confirm_email")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cleanup_expired_email_tokens() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Create a token (it will be valid for 15 minutes)
        let _token = storage
            .create_email_token("did:plc:test", "confirm_email")
            .unwrap();

        // Cleanup should not remove non-expired tokens
        let removed = storage.cleanup_expired_email_tokens().unwrap();
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_wipe_account_data() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Populate various tables
        storage.put_setting("email", "test@example.com").unwrap();
        storage.put_block("bafytest", &[1, 2, 3], None).unwrap();
        storage
            .create_email_token("did:plc:test", "confirm_email")
            .unwrap();

        // Wipe everything
        storage.wipe_account_data().unwrap();

        // Settings should be gone
        let email = storage.get_setting("email").unwrap();
        assert!(email.is_none());

        // Blocks should be gone
        let block = storage.get_block("bafytest").unwrap();
        assert!(block.is_none());
    }

    #[test]
    fn test_invite_code_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Create a code
        storage
            .create_invite_code("test-abc-12345", 2, "", "admin")
            .unwrap();

        // Retrieve it
        let code = storage.get_invite_code("test-abc-12345").unwrap().unwrap();
        assert_eq!(code.code, "test-abc-12345");
        assert_eq!(code.available_uses, 2);
        assert!(!code.disabled);
        assert_eq!(code.use_count, 0);

        // Non-existent code returns None
        assert!(storage.get_invite_code("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_invite_code_use() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .create_invite_code("test-use-code1", 2, "", "admin")
            .unwrap();

        // Use the code
        assert!(storage
            .use_invite_code("test-use-code1", "did:plc:user1")
            .unwrap());

        // Check use count
        let code = storage.get_invite_code("test-use-code1").unwrap().unwrap();
        assert_eq!(code.use_count, 1);

        // Use again (should succeed, 2 uses available)
        assert!(storage
            .use_invite_code("test-use-code1", "did:plc:user2")
            .unwrap());

        // Third use should fail (only 2 uses allowed)
        assert!(!storage
            .use_invite_code("test-use-code1", "did:plc:user3")
            .unwrap());
    }

    #[test]
    fn test_invite_code_disable() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .create_invite_code("test-dis-code1", 5, "", "admin")
            .unwrap();

        // Disable the code
        assert!(storage.disable_invite_code("test-dis-code1").unwrap());

        // Using disabled code should fail
        assert!(!storage
            .use_invite_code("test-dis-code1", "did:plc:user1")
            .unwrap());
    }

    #[test]
    fn test_invite_code_list() {
        let storage = SqliteStorage::in_memory().unwrap();

        storage
            .create_invite_code("code-a", 1, "did:plc:alice", "admin")
            .unwrap();
        storage
            .create_invite_code("code-b", 1, "did:plc:bob", "admin")
            .unwrap();
        storage
            .create_invite_code("code-c", 1, "did:plc:alice", "admin")
            .unwrap();

        // List all
        let all = storage.list_invite_codes("").unwrap();
        assert_eq!(all.len(), 3);

        // List for alice
        let alice = storage.list_invite_codes("did:plc:alice").unwrap();
        assert_eq!(alice.len(), 2);

        // List for bob
        let bob = storage.list_invite_codes("did:plc:bob").unwrap();
        assert_eq!(bob.len(), 1);
    }

    #[test]
    fn test_invite_code_invalid_returns_false() {
        let storage = SqliteStorage::in_memory().unwrap();

        // Using non-existent code should return false
        assert!(!storage
            .use_invite_code("nonexistent", "did:plc:user1")
            .unwrap());
    }

    #[test]
    fn test_account_entry_crud() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:abc123".to_string(),
            handle: "alice.test".to_string(),
            email: Some("alice@example.com".to_string()),
            password_hash: "$2b$12$testhash".to_string(),
            signing_key_hex: Some("deadbeef".to_string()),
            recovery_key_hex: Some("cafebabe".to_string()),
            invite_code: Some("inv-123".to_string()),
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };

        // Create
        storage.create_account_entry(&entry).unwrap();

        // Get by DID
        let found = storage
            .get_account_by_did("did:plc:abc123")
            .unwrap()
            .unwrap();
        assert_eq!(found.did, "did:plc:abc123");
        assert_eq!(found.handle, "alice.test");
        assert_eq!(found.email.as_deref(), Some("alice@example.com"));
        assert!(!found.email_confirmed);
        assert_eq!(found.status, AccountStatus::Active);

        // Get by handle
        let found = storage
            .get_account_by_handle("alice.test")
            .unwrap()
            .unwrap();
        assert_eq!(found.did, "did:plc:abc123");

        // Get by identifier (DID)
        let found = storage
            .get_account_by_identifier("did:plc:abc123")
            .unwrap()
            .unwrap();
        assert_eq!(found.handle, "alice.test");

        // Get by identifier (handle)
        let found = storage
            .get_account_by_identifier("alice.test")
            .unwrap()
            .unwrap();
        assert_eq!(found.did, "did:plc:abc123");
    }

    #[test]
    fn test_account_not_found() {
        let storage = SqliteStorage::in_memory().unwrap();

        assert!(storage
            .get_account_by_did("did:plc:nonexistent")
            .unwrap()
            .is_none());
        assert!(storage
            .get_account_by_handle("nobody.test")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_account_duplicate_did_rejected() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:dup".to_string(),
            handle: "user1.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry).unwrap();

        let dup = AccountEntry {
            did: "did:plc:dup".to_string(),
            handle: "user2.test".to_string(),
            ..entry
        };
        assert!(storage.create_account_entry(&dup).is_err());
    }

    #[test]
    fn test_account_duplicate_handle_rejected() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry1 = AccountEntry {
            did: "did:plc:one".to_string(),
            handle: "same.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry1).unwrap();

        let entry2 = AccountEntry {
            did: "did:plc:two".to_string(),
            handle: "same.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        assert!(storage.create_account_entry(&entry2).is_err());
    }

    #[test]
    fn test_account_update_handle() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:upd".to_string(),
            handle: "old.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry).unwrap();

        assert!(storage
            .update_account_handle_entry("did:plc:upd", "new.test")
            .unwrap());

        let found = storage.get_account_by_did("did:plc:upd").unwrap().unwrap();
        assert_eq!(found.handle, "new.test");

        // Old handle should no longer find the account
        assert!(storage.get_account_by_handle("old.test").unwrap().is_none());
    }

    #[test]
    fn test_account_update_status() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:status".to_string(),
            handle: "status.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry).unwrap();

        storage
            .update_account_status("did:plc:status", AccountStatus::Suspended)
            .unwrap();

        let found = storage
            .get_account_by_did("did:plc:status")
            .unwrap()
            .unwrap();
        assert_eq!(found.status, AccountStatus::Suspended);
    }

    #[test]
    fn test_account_confirm_email() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:email".to_string(),
            handle: "email.test".to_string(),
            email: Some("test@example.com".to_string()),
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry).unwrap();

        assert!(
            !storage
                .get_account_by_did("did:plc:email")
                .unwrap()
                .unwrap()
                .email_confirmed
        );

        storage.confirm_account_email("did:plc:email").unwrap();

        assert!(
            storage
                .get_account_by_did("did:plc:email")
                .unwrap()
                .unwrap()
                .email_confirmed
        );
    }

    #[test]
    fn test_account_list_and_count() {
        let storage = SqliteStorage::in_memory().unwrap();

        for i in 0..5 {
            let entry = AccountEntry {
                did: format!("did:plc:user{i}"),
                handle: format!("user{i}.test"),
                email: None,
                password_hash: "hash".to_string(),
                signing_key_hex: None,
                recovery_key_hex: None,
                invite_code: None,
                email_confirmed: false,
                status: if i < 3 {
                    AccountStatus::Active
                } else {
                    AccountStatus::Suspended
                },
                created_at: None,
                deactivated_at: None,
            };
            storage.create_account_entry(&entry).unwrap();
        }

        assert_eq!(storage.get_account_count().unwrap(), 5);

        // List all
        let all = storage.list_accounts(None, 100, None).unwrap();
        assert_eq!(all.len(), 5);

        // List only active
        let active = storage
            .list_accounts(Some(AccountStatus::Active), 100, None)
            .unwrap();
        assert_eq!(active.len(), 3);

        // List only suspended
        let suspended = storage
            .list_accounts(Some(AccountStatus::Suspended), 100, None)
            .unwrap();
        assert_eq!(suspended.len(), 2);

        // List with limit
        let limited = storage.list_accounts(None, 2, None).unwrap();
        assert_eq!(limited.len(), 2);

        // List with cursor (pagination)
        let page2 = storage
            .list_accounts(None, 2, Some(&limited[1].did))
            .unwrap();
        assert_eq!(page2.len(), 2);
        assert_ne!(page2[0].did, limited[1].did);
    }

    #[test]
    fn test_account_delete() {
        let storage = SqliteStorage::in_memory().unwrap();

        let entry = AccountEntry {
            did: "did:plc:del".to_string(),
            handle: "del.test".to_string(),
            email: None,
            password_hash: "hash".to_string(),
            signing_key_hex: None,
            recovery_key_hex: None,
            invite_code: None,
            email_confirmed: false,
            status: AccountStatus::Active,
            created_at: None,
            deactivated_at: None,
        };
        storage.create_account_entry(&entry).unwrap();

        assert!(storage.delete_account_entry("did:plc:del").unwrap());
        assert!(storage.get_account_by_did("did:plc:del").unwrap().is_none());

        // Double delete returns false
        assert!(!storage.delete_account_entry("did:plc:del").unwrap());
    }
}
