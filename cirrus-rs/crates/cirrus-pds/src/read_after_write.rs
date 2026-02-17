//! Read-after-write consistency layer.
//!
//! When a user writes data to the PDS (create post, update profile), there is
//! a propagation delay before the AppView indexes the change. The RAW layer
//! intercepts proxied responses, checks the AppView's repo revision via the
//! `atproto-repo-rev` header, and merges any locally-written records that the
//! AppView hasn't indexed yet.

use serde_json::Value;
use tracing::debug;

use crate::storage::{LocalRecordEntry, SqliteStorage};

/// Collected local records since a given repo revision, categorized by type.
pub struct LocalRecords {
    /// Updated profile record, if any.
    pub profile: Option<LocalRecordEntry>,
    /// New posts since the revision.
    pub posts: Vec<LocalRecordEntry>,
    /// Total count of local records found.
    pub count: usize,
}

/// Endpoints that support read-after-write munging.
pub fn needs_read_after_write(nsid: &str) -> bool {
    matches!(
        nsid,
        "app.bsky.actor.getProfile"
            | "app.bsky.actor.getProfiles"
            | "app.bsky.feed.getTimeline"
            | "app.bsky.feed.getAuthorFeed"
    )
}

/// Extracts the `atproto-repo-rev` header value from a response.
pub fn get_repo_rev(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("atproto-repo-rev")
        .and_then(|v| v.to_str().ok())
}

/// Fetches local records written since the given revision, categorized
/// into profile updates and new posts.
pub fn get_local_records(storage: &SqliteStorage, since_rev: &str) -> LocalRecords {
    let entries = match storage.get_records_since_rev(since_rev) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "failed to fetch local records since rev");
            return LocalRecords {
                profile: None,
                posts: Vec::new(),
                count: 0,
            };
        }
    };

    let count = entries.len();
    let mut profile = None;
    let mut posts = Vec::new();

    for entry in entries {
        match entry.collection.as_str() {
            "app.bsky.actor.profile" if entry.rkey == "self" => {
                profile = Some(entry);
            }
            "app.bsky.feed.post" => {
                posts.push(entry);
            }
            _ => {} // Other collections don't need RAW
        }
    }

    LocalRecords {
        profile,
        posts,
        count,
    }
}

/// Munges an AppView response with local data based on the endpoint.
///
/// Returns `None` if no munging was performed (response unchanged).
pub fn munge_response(
    nsid: &str,
    mut response: Value,
    local: &LocalRecords,
    requester_did: &str,
    handle: &str,
) -> Option<Value> {
    if local.count == 0 {
        return None;
    }

    match nsid {
        "app.bsky.actor.getProfile" => munge_get_profile(&mut response, local, requester_did),
        "app.bsky.actor.getProfiles" => munge_get_profiles(&mut response, local, requester_did),
        "app.bsky.feed.getTimeline" => munge_timeline(&mut response, local, requester_did, handle),
        "app.bsky.feed.getAuthorFeed" => {
            munge_author_feed(&mut response, local, requester_did, handle)
        }
        _ => return None,
    }

    Some(response)
}

/// Merges local profile data into a getProfile response.
fn munge_get_profile(response: &mut Value, local: &LocalRecords, requester_did: &str) {
    let Some(ref profile_entry) = local.profile else {
        return;
    };

    // Only munge our own profile
    if response.get("did").and_then(Value::as_str) != Some(requester_did) {
        return;
    }

    let record = match decode_record(&profile_entry.bytes) {
        Some(r) => r,
        None => return,
    };

    apply_profile_fields(response, &record);
}

/// Merges local profile data into a getProfiles response.
fn munge_get_profiles(response: &mut Value, local: &LocalRecords, requester_did: &str) {
    let Some(ref profile_entry) = local.profile else {
        return;
    };

    let record = match decode_record(&profile_entry.bytes) {
        Some(r) => r,
        None => return,
    };

    let Some(profiles) = response.get_mut("profiles").and_then(Value::as_array_mut) else {
        return;
    };

    for profile in profiles {
        if profile.get("did").and_then(Value::as_str) == Some(requester_did) {
            apply_profile_fields(profile, &record);
        }
    }
}

/// Applies local profile record fields to a profile view.
fn apply_profile_fields(view: &mut Value, record: &Value) {
    if let Some(display_name) = record.get("displayName") {
        view["displayName"] = display_name.clone();
    }
    if let Some(description) = record.get("description") {
        view["description"] = description.clone();
    }
    // Avatar and banner are blob references — we can't generate CDN URLs
    // locally, so we only update text fields.
}

/// Inserts local posts into a getTimeline feed response.
fn munge_timeline(response: &mut Value, local: &LocalRecords, requester_did: &str, handle: &str) {
    if local.posts.is_empty() {
        return;
    }

    let Some(feed) = response.get_mut("feed").and_then(Value::as_array_mut) else {
        return;
    };

    insert_posts_into_feed(feed, &local.posts, requester_did, handle);
}

/// Inserts local posts into a getAuthorFeed response (only for own feed).
fn munge_author_feed(
    response: &mut Value,
    local: &LocalRecords,
    requester_did: &str,
    handle: &str,
) {
    if local.posts.is_empty() {
        return;
    }

    // Only insert into our own author feed
    // The actor DID is typically embedded in the first feed item
    let is_own_feed = response
        .get("feed")
        .and_then(Value::as_array)
        .and_then(|f| f.first())
        .and_then(|item| item.get("post"))
        .and_then(|post| post.get("author"))
        .and_then(|author| author.get("did"))
        .and_then(Value::as_str)
        .map_or(true, |did| did == requester_did); // If feed is empty, it's our feed

    if !is_own_feed {
        return;
    }

    let Some(feed) = response.get_mut("feed").and_then(Value::as_array_mut) else {
        return;
    };

    insert_posts_into_feed(feed, &local.posts, requester_did, handle);
}

/// Inserts local posts at the beginning of a feed array.
///
/// Only inserts posts that are newer than the most recent item in the feed
/// (based on `indexedAt` timestamp comparison).
fn insert_posts_into_feed(
    feed: &mut Vec<Value>,
    posts: &[LocalRecordEntry],
    requester_did: &str,
    handle: &str,
) {
    // Find the newest timestamp in the existing feed
    let newest_in_feed = feed
        .first()
        .and_then(|item| item.get("post"))
        .and_then(|post| post.get("indexedAt"))
        .and_then(Value::as_str)
        .unwrap_or("");

    // Build minimal FeedViewPost objects for local posts that are newer
    let mut new_items: Vec<Value> = Vec::new();
    for entry in posts.iter().rev() {
        // Only insert posts newer than what the feed already has
        if !newest_in_feed.is_empty() && entry.indexed_at.as_str() <= newest_in_feed {
            continue;
        }

        let record = match decode_record(&entry.bytes) {
            Some(r) => r,
            None => continue,
        };

        let uri = format!("at://{}/app.bsky.feed.post/{}", requester_did, entry.rkey);

        let feed_item = serde_json::json!({
            "post": {
                "uri": uri,
                "cid": entry.cid,
                "author": {
                    "did": requester_did,
                    "handle": handle,
                    "viewer": {},
                    "labels": []
                },
                "record": record,
                "indexedAt": entry.indexed_at,
                "replyCount": 0,
                "repostCount": 0,
                "likeCount": 0,
                "quoteCount": 0,
                "labels": []
            }
        });

        new_items.push(feed_item);
    }

    if !new_items.is_empty() {
        // Prepend local posts to the feed (they're newer)
        new_items.append(feed);
        *feed = new_items;
    }
}

/// Decodes CBOR bytes into a JSON value.
fn decode_record(bytes: &[u8]) -> Option<Value> {
    cirrus_common::cbor::decode(bytes).ok()
}

/// Calculates the upstream lag in milliseconds from local records.
///
/// Returns the age of the oldest local record that the AppView hasn't indexed.
pub fn get_local_lag(local: &LocalRecords) -> Option<u64> {
    if local.count == 0 {
        return None;
    }

    // Find the oldest indexed_at among local records
    let oldest = local
        .posts
        .iter()
        .map(|p| p.indexed_at.as_str())
        .chain(local.profile.as_ref().map(|p| p.indexed_at.as_str()))
        .min()?;

    // Parse and compute lag
    let parsed = chrono::NaiveDateTime::parse_from_str(oldest, "%Y-%m-%d %H:%M:%S").ok()?;
    let now = chrono::Utc::now().naive_utc();
    let lag = now.signed_duration_since(parsed);
    Some(lag.num_milliseconds().max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_read_after_write() {
        assert!(needs_read_after_write("app.bsky.actor.getProfile"));
        assert!(needs_read_after_write("app.bsky.actor.getProfiles"));
        assert!(needs_read_after_write("app.bsky.feed.getTimeline"));
        assert!(needs_read_after_write("app.bsky.feed.getAuthorFeed"));

        assert!(!needs_read_after_write("app.bsky.feed.getPostThread"));
        assert!(!needs_read_after_write("com.atproto.repo.getRecord"));
        assert!(!needs_read_after_write("app.bsky.graph.getFollowers"));
    }

    #[test]
    fn test_munge_get_profile_updates_fields() {
        let profile_bytes = cirrus_common::cbor::encode(&serde_json::json!({
            "$type": "app.bsky.actor.profile",
            "displayName": "New Name",
            "description": "Updated bio"
        }))
        .unwrap();

        let local = LocalRecords {
            profile: Some(LocalRecordEntry {
                collection: "app.bsky.actor.profile".into(),
                rkey: "self".into(),
                cid: "bafytest".into(),
                bytes: profile_bytes,
                indexed_at: "2026-02-16 12:00:00".into(),
            }),
            posts: Vec::new(),
            count: 1,
        };

        let mut response = serde_json::json!({
            "did": "did:plc:test",
            "handle": "test.bsky.social",
            "displayName": "Old Name",
            "description": "Old bio"
        });

        let result = munge_response(
            "app.bsky.actor.getProfile",
            response.clone(),
            &local,
            "did:plc:test",
            "test.bsky.social",
        );

        assert!(result.is_some());
        let munged = result.unwrap();
        assert_eq!(munged["displayName"], "New Name");
        assert_eq!(munged["description"], "Updated bio");

        // Should not munge if different DID
        response["did"] = serde_json::json!("did:plc:other");
        let result = munge_response(
            "app.bsky.actor.getProfile",
            response,
            &local,
            "did:plc:test",
            "test.bsky.social",
        );
        assert!(result.is_some()); // returns Some but profile fields unchanged
    }

    #[test]
    fn test_munge_timeline_inserts_posts() {
        let post_bytes = cirrus_common::cbor::encode(&serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "new local post",
            "createdAt": "2026-02-16T12:00:00Z"
        }))
        .unwrap();

        let local = LocalRecords {
            profile: None,
            posts: vec![LocalRecordEntry {
                collection: "app.bsky.feed.post".into(),
                rkey: "tid123".into(),
                cid: "bafypostcid".into(),
                bytes: post_bytes,
                indexed_at: "2026-02-16 12:00:00".into(),
            }],
            count: 1,
        };

        let response = serde_json::json!({
            "feed": [
                {
                    "post": {
                        "uri": "at://did:plc:other/app.bsky.feed.post/old",
                        "cid": "bafyold",
                        "author": { "did": "did:plc:other", "handle": "other.bsky.social" },
                        "record": { "text": "old post" },
                        "indexedAt": "2026-02-16 11:00:00"
                    }
                }
            ]
        });

        let result = munge_response(
            "app.bsky.feed.getTimeline",
            response,
            &local,
            "did:plc:test",
            "test.bsky.social",
        );

        assert!(result.is_some());
        let munged = result.unwrap();
        let feed = munged["feed"].as_array().unwrap();
        assert_eq!(feed.len(), 2);
        // Local post should be first (prepended)
        assert_eq!(feed[0]["post"]["record"]["text"], "new local post");
        assert_eq!(
            feed[0]["post"]["uri"],
            "at://did:plc:test/app.bsky.feed.post/tid123"
        );
    }

    #[test]
    fn test_no_munge_when_no_local_records() {
        let local = LocalRecords {
            profile: None,
            posts: Vec::new(),
            count: 0,
        };

        let response = serde_json::json!({
            "did": "did:plc:test",
            "handle": "test.bsky.social"
        });

        let result = munge_response(
            "app.bsky.actor.getProfile",
            response,
            &local,
            "did:plc:test",
            "test.bsky.social",
        );

        assert!(result.is_none());
    }
}
