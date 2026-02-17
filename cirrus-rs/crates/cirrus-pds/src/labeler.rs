//! Labeler and moderation service integration.
//!
//! Implements the AT Protocol label system for content moderation:
//! - Label data model (`com.atproto.label.defs#label`)
//! - Label querying (`com.atproto.label.queryLabels`)
//! - Label streaming (`com.atproto.label.subscribeLabels`)
//! - Label storage and retrieval
//! - External labeler subscription

use serde::{Deserialize, Serialize};

/// A content label as defined by `com.atproto.label.defs#label`.
///
/// Metadata tag on an AT Protocol resource (repo, record, or other).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    /// The AT Protocol version of the label object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ver: Option<i64>,
    /// DID of the actor who created this label.
    pub src: String,
    /// AT URI of the resource this label applies to.
    pub uri: String,
    /// CID of the specific version of the resource (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// The short string name of the value or type of this label (max 128 chars).
    pub val: String,
    /// If true, this is a negation label overwriting a previous label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neg: Option<bool>,
    /// Timestamp when this label was created (ISO 8601).
    pub cts: String,
    /// Timestamp at which this label expires (ISO 8601, optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
    /// Signature of the DAG-CBOR encoded label (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Self-labels published by the author within a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfLabels {
    /// List of self-label values (max 10).
    pub values: Vec<SelfLabel>,
}

/// A single self-label value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfLabel {
    /// The short string name of the label value (max 128 chars).
    pub val: String,
}

/// Label value definition for labeler service declarations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelValueDefinition {
    /// The label value identifier (lowercase ascii + hyphens, max 100 chars).
    pub identifier: String,
    /// Visual severity: "inform", "alert", or "none".
    pub severity: String,
    /// What to blur: "content", "media", or "none".
    pub blurs: String,
    /// Default client setting (optional).
    #[serde(rename = "defaultSetting", skip_serializing_if = "Option::is_none")]
    pub default_setting: Option<String>,
    /// Whether this label can only be applied by adults (optional).
    #[serde(rename = "adultOnly", skip_serializing_if = "Option::is_none")]
    pub adult_only: Option<bool>,
    /// Localized name and description.
    pub locales: Vec<LabelValueDefinitionStrings>,
}

/// Localized strings for a label value definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelValueDefinitionStrings {
    /// Language code (BCP 47).
    pub lang: String,
    /// Human-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
}

/// Parameters for `com.atproto.label.queryLabels`.
#[derive(Debug, Clone, Deserialize)]
pub struct QueryLabelsParams {
    /// List of AT URI patterns to match (boolean OR).
    #[serde(rename = "uriPatterns")]
    pub uri_patterns: Vec<String>,
    /// Optional list of label source DIDs to filter on.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Maximum number of labels to return (1-250, default 50).
    pub limit: Option<i64>,
    /// Pagination cursor.
    pub cursor: Option<String>,
}

/// Output for `com.atproto.label.queryLabels`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLabelsOutput {
    /// Pagination cursor for next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// Matching labels.
    pub labels: Vec<Label>,
}

/// A sequenced label event for `subscribeLabels`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelEvent {
    /// Sequence number.
    pub seq: i64,
    /// Labels in this event.
    pub labels: Vec<Label>,
}

/// Label storage backed by `SQLite`.
///
/// Stores labels received from external labeling services and
/// self-labels created by the PDS.
pub struct LabelStore {
    conn: parking_lot::Mutex<rusqlite::Connection>,
}

impl LabelStore {
    /// Creates a new in-memory label store.
    ///
    /// # Errors
    /// Returns an error if database initialization fails.
    pub fn in_memory() -> crate::error::Result<Self> {
        let conn = rusqlite::Connection::open_in_memory()?;
        let store = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Creates a new label store backed by a file.
    ///
    /// # Errors
    /// Returns an error if the database cannot be opened or initialized.
    pub fn open(path: &str) -> crate::error::Result<Self> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        let store = Self {
            conn: parking_lot::Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> crate::error::Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS labels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src TEXT NOT NULL,
                uri TEXT NOT NULL,
                cid TEXT,
                val TEXT NOT NULL,
                neg INTEGER NOT NULL DEFAULT 0,
                cts TEXT NOT NULL,
                exp TEXT,
                sig TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_labels_uri ON labels(uri);
            CREATE INDEX IF NOT EXISTS idx_labels_src ON labels(src);
            CREATE INDEX IF NOT EXISTS idx_labels_val ON labels(val);
            CREATE INDEX IF NOT EXISTS idx_labels_src_uri_val ON labels(src, uri, val);",
        )?;
        Ok(())
    }

    /// Stores a label.
    ///
    /// # Errors
    /// Returns an error if the insert fails.
    pub fn create_label(&self, label: &Label) -> crate::error::Result<i64> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO labels (src, uri, cid, val, neg, cts, exp, sig) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                label.src,
                label.uri,
                label.cid,
                label.val,
                i32::from(label.neg.unwrap_or(false)),
                label.cts,
                label.exp,
                label.sig,
            ],
        )?;
        let id = conn.last_insert_rowid();
        Ok(id)
    }

    /// Queries labels matching the given URI patterns and optional source filter.
    ///
    /// URI patterns support prefix matching with a trailing `*`.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn query_labels(
        &self,
        uri_patterns: &[String],
        sources: &[String],
        limit: i64,
        cursor: Option<&str>,
    ) -> crate::error::Result<(Vec<Label>, Option<String>)> {
        let conn = self.conn.lock();

        // Build WHERE clause dynamically
        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        // URI pattern matching (OR logic)
        if !uri_patterns.is_empty() {
            let mut uri_conds: Vec<String> = Vec::new();
            for pattern in uri_patterns {
                if let Some(prefix) = pattern.strip_suffix('*') {
                    uri_conds.push("uri LIKE ?".to_string());
                    params.push(Box::new(format!("{prefix}%")));
                } else {
                    uri_conds.push("uri = ?".to_string());
                    params.push(Box::new(pattern.clone()));
                }
            }
            conditions.push(format!("({})", uri_conds.join(" OR ")));
        }

        // Source filter (OR logic)
        if !sources.is_empty() {
            let placeholders: Vec<&str> = sources.iter().map(|_| "?").collect();
            conditions.push(format!("src IN ({})", placeholders.join(", ")));
            for src in sources {
                params.push(Box::new(src.clone()));
            }
        }

        // Cursor-based pagination
        if let Some(c) = cursor {
            if let Ok(id) = c.parse::<i64>() {
                conditions.push("id > ?".to_string());
                params.push(Box::new(id));
            }
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!(
            "SELECT id, src, uri, cid, val, neg, cts, exp, sig FROM labels {where_clause} ORDER BY id LIMIT ?"
        );
        params.push(Box::new(limit));

        let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&query)?;

        let labels: Vec<(i64, Label)> = stmt
            .query_map(param_refs.as_slice(), |row| {
                let id: i64 = row.get(0)?;
                let neg_int: i32 = row.get(5)?;
                Ok((
                    id,
                    Label {
                        ver: Some(1),
                        src: row.get(1)?,
                        uri: row.get(2)?,
                        cid: row.get(3)?,
                        val: row.get(4)?,
                        neg: if neg_int != 0 { Some(true) } else { None },
                        cts: row.get(6)?,
                        exp: row.get(7)?,
                        sig: row.get(8)?,
                    },
                ))
            })?
            .filter_map(std::result::Result::ok)
            .collect();

        let next_cursor = labels.last().map(|(id, _)| id.to_string());
        let label_values: Vec<Label> = labels.into_iter().map(|(_, l)| l).collect();

        Ok((label_values, next_cursor))
    }

    /// Returns labels for a specific URI, optionally filtered by source.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn get_labels_for_uri(
        &self,
        uri: &str,
        src: Option<&str>,
    ) -> crate::error::Result<Vec<Label>> {
        let conn = self.conn.lock();

        let (query, needs_src) = if src.is_some() {
            (
                "SELECT src, uri, cid, val, neg, cts, exp, sig FROM labels WHERE uri = ? AND src = ? ORDER BY id",
                true,
            )
        } else {
            (
                "SELECT src, uri, cid, val, neg, cts, exp, sig FROM labels WHERE uri = ? ORDER BY id",
                false,
            )
        };

        let mut stmt = conn.prepare(query)?;

        let row_mapper = |row: &rusqlite::Row<'_>| {
            let neg_int: i32 = row.get(4)?;
            Ok(Label {
                ver: Some(1),
                src: row.get(0)?,
                uri: row.get(1)?,
                cid: row.get(2)?,
                val: row.get(3)?,
                neg: if neg_int != 0 { Some(true) } else { None },
                cts: row.get(5)?,
                exp: row.get(6)?,
                sig: row.get(7)?,
            })
        };

        let labels: Vec<Label> = if needs_src {
            let v: Vec<Label> = stmt
                .query_map(rusqlite::params![uri, src], row_mapper)?
                .filter_map(std::result::Result::ok)
                .collect();
            v
        } else {
            let v: Vec<Label> = stmt
                .query_map(rusqlite::params![uri], row_mapper)?
                .filter_map(std::result::Result::ok)
                .collect();
            v
        };

        Ok(labels)
    }

    /// Returns the total count of labels.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub fn label_count(&self) -> crate::error::Result<i64> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM labels", [], |row| row.get(0))?;
        Ok(count)
    }
}

/// Configuration for subscribing to an external labeling service.
#[derive(Debug, Clone)]
pub struct LabelerConfig {
    /// DID of the labeling service.
    pub did: String,
    /// HTTP endpoint of the labeling service.
    pub endpoint: String,
    /// Whether to subscribe to the label stream.
    pub subscribe: bool,
}

/// Client for interacting with external labeling services.
pub struct LabelerClient {
    config: LabelerConfig,
    client: reqwest::Client,
}

impl LabelerClient {
    /// Creates a new labeler client.
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created.
    pub fn new(config: LabelerConfig) -> crate::error::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| crate::error::PdsError::Http(format!("failed to create client: {e}")))?;

        Ok(Self { config, client })
    }

    /// Returns the labeler configuration.
    #[must_use]
    pub fn config(&self) -> &LabelerConfig {
        &self.config
    }

    /// Fetches labels from the labeling service.
    ///
    /// # Errors
    /// Returns an error if the HTTP request fails.
    pub async fn query_labels(
        &self,
        uri_patterns: &[String],
        limit: Option<i64>,
        cursor: Option<&str>,
    ) -> crate::error::Result<QueryLabelsOutput> {
        let base_url = format!(
            "{}/xrpc/com.atproto.label.queryLabels",
            self.config.endpoint
        );

        let mut request = self.client.get(&base_url);

        // Add URI patterns as repeated query params
        let mut pairs: Vec<(String, String)> = Vec::new();
        for pattern in uri_patterns {
            pairs.push(("uriPatterns".to_string(), pattern.clone()));
        }
        if let Some(l) = limit {
            pairs.push(("limit".to_string(), l.to_string()));
        }
        if let Some(c) = cursor {
            pairs.push(("cursor".to_string(), c.to_string()));
        }
        request = request.query(&pairs);

        let response = request
            .send()
            .await
            .map_err(|e| crate::error::PdsError::Http(format!("labeler request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(crate::error::PdsError::Http(format!(
                "labeler returned {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| crate::error::PdsError::Http(format!("invalid labeler response: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_label(src: &str, uri: &str, val: &str) -> Label {
        Label {
            ver: Some(1),
            src: src.to_string(),
            uri: uri.to_string(),
            cid: None,
            val: val.to_string(),
            neg: None,
            cts: "2026-01-01T00:00:00Z".to_string(),
            exp: None,
            sig: None,
        }
    }

    #[test]
    fn test_label_serialization() {
        let label = make_label("did:plc:labeler1", "at://did:plc:user1/app.bsky.feed.post/abc", "spam");
        let json = serde_json::to_string(&label).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed["src"], "did:plc:labeler1");
        assert_eq!(parsed["val"], "spam");
        assert!(parsed.get("neg").is_none()); // None should be skipped
    }

    #[test]
    fn test_label_negation_serialization() {
        let mut label = make_label("did:plc:labeler1", "at://did:plc:user1/app.bsky.feed.post/abc", "spam");
        label.neg = Some(true);
        let json = serde_json::to_string(&label).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed["neg"], true);
    }

    #[test]
    fn test_label_store_create_and_query() {
        let store = LabelStore::in_memory().expect("should create store");

        store
            .create_label(&make_label(
                "did:plc:mod",
                "at://did:plc:user1/app.bsky.feed.post/abc",
                "spam",
            ))
            .expect("should insert");

        store
            .create_label(&make_label(
                "did:plc:mod",
                "at://did:plc:user2/app.bsky.feed.post/xyz",
                "nsfw",
            ))
            .expect("should insert");

        // Query all labels for user1
        let (labels, _cursor) = store
            .query_labels(
                &["at://did:plc:user1/*".to_string()],
                &[],
                50,
                None,
            )
            .expect("should query");

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].val, "spam");
    }

    #[test]
    fn test_label_store_exact_uri_query() {
        let store = LabelStore::in_memory().expect("should create store");

        store
            .create_label(&make_label(
                "did:plc:mod",
                "at://did:plc:user1/app.bsky.feed.post/abc",
                "spam",
            ))
            .expect("should insert");

        store
            .create_label(&make_label(
                "did:plc:mod",
                "at://did:plc:user1/app.bsky.feed.post/def",
                "nsfw",
            ))
            .expect("should insert");

        // Exact URI match
        let (labels, _) = store
            .query_labels(
                &["at://did:plc:user1/app.bsky.feed.post/abc".to_string()],
                &[],
                50,
                None,
            )
            .expect("should query");

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].val, "spam");
    }

    #[test]
    fn test_label_store_source_filter() {
        let store = LabelStore::in_memory().expect("should create store");

        store
            .create_label(&make_label("did:plc:mod1", "at://did:plc:user1", "spam"))
            .expect("should insert");
        store
            .create_label(&make_label("did:plc:mod2", "at://did:plc:user1", "nsfw"))
            .expect("should insert");

        // Filter by source
        let (labels, _) = store
            .query_labels(
                &["at://did:plc:user1".to_string()],
                &["did:plc:mod1".to_string()],
                50,
                None,
            )
            .expect("should query");

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].src, "did:plc:mod1");
    }

    #[test]
    fn test_label_store_pagination() {
        let store = LabelStore::in_memory().expect("should create store");

        for i in 0..10 {
            store
                .create_label(&make_label(
                    "did:plc:mod",
                    &format!("at://did:plc:user1/app.bsky.feed.post/{i}"),
                    "test",
                ))
                .expect("should insert");
        }

        // First page
        let (page1, cursor1) = store
            .query_labels(
                &["at://did:plc:user1/*".to_string()],
                &[],
                3,
                None,
            )
            .expect("should query");

        assert_eq!(page1.len(), 3);
        assert!(cursor1.is_some());

        // Second page
        let (page2, cursor2) = store
            .query_labels(
                &["at://did:plc:user1/*".to_string()],
                &[],
                3,
                cursor1.as_deref(),
            )
            .expect("should query");

        assert_eq!(page2.len(), 3);
        assert!(cursor2.is_some());

        // URIs should not overlap
        assert_ne!(page1[0].uri, page2[0].uri);
    }

    #[test]
    fn test_label_store_get_for_uri() {
        let store = LabelStore::in_memory().expect("should create store");

        store
            .create_label(&make_label("did:plc:mod", "at://did:plc:user1", "spam"))
            .expect("should insert");
        store
            .create_label(&make_label("did:plc:mod", "at://did:plc:user1", "nsfw"))
            .expect("should insert");
        store
            .create_label(&make_label("did:plc:other", "at://did:plc:user1", "gore"))
            .expect("should insert");

        // All labels for URI
        let labels = store
            .get_labels_for_uri("at://did:plc:user1", None)
            .expect("should query");
        assert_eq!(labels.len(), 3);

        // Filtered by source
        let labels = store
            .get_labels_for_uri("at://did:plc:user1", Some("did:plc:mod"))
            .expect("should query");
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn test_label_store_count() {
        let store = LabelStore::in_memory().expect("should create store");

        assert_eq!(store.label_count().unwrap(), 0);

        store
            .create_label(&make_label("did:plc:mod", "at://did:plc:user1", "spam"))
            .unwrap();
        store
            .create_label(&make_label("did:plc:mod", "at://did:plc:user2", "nsfw"))
            .unwrap();

        assert_eq!(store.label_count().unwrap(), 2);
    }

    #[test]
    fn test_self_labels() {
        let labels = SelfLabels {
            values: vec![
                SelfLabel {
                    val: "nudity".to_string(),
                },
                SelfLabel {
                    val: "sexual".to_string(),
                },
            ],
        };

        let json = serde_json::to_string(&labels).expect("should serialize");
        let parsed: SelfLabels = serde_json::from_str(&json).expect("should parse");
        assert_eq!(parsed.values.len(), 2);
        assert_eq!(parsed.values[0].val, "nudity");
    }

    #[test]
    fn test_labeler_config() {
        let config = LabelerConfig {
            did: "did:plc:labeler".to_string(),
            endpoint: "https://labeler.example.com".to_string(),
            subscribe: true,
        };
        assert!(config.subscribe);
        assert_eq!(config.did, "did:plc:labeler");
    }
}
