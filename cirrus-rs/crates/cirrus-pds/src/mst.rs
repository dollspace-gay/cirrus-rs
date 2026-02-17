//! Merkle Search Tree (MST) for AT Protocol repositories.
//!
//! The MST is a content-addressed search tree that indexes all records in a
//! repository by their path (collection/rkey). The commit's `data` CID points
//! to the MST root.
//!
//! Key placement is determined by counting leading zero-pairs in SHA-256(key),
//! producing a "layer" value. Most keys are layer 0 (leaves); higher-layer
//! keys split the tree into subtrees.

use ciborium::Value as CborValue;
use cirrus_common::cid::{sha256, Cid};

/// Encodes a CID as a DAG-CBOR link (CBOR tag 42 with 0x00 prefix).
fn cid_link(cid: &Cid) -> CborValue {
    let mut bytes = vec![0x00]; // identity multibase prefix
    bytes.extend_from_slice(&cid.to_bytes());
    CborValue::Tag(42, Box::new(CborValue::Bytes(bytes)))
}

/// Computes the MST layer for a key by counting leading zero-pairs in SHA-256(key).
///
/// Each byte of the hash contributes 0–4 zero-pairs (groups of 2 zero bits).
fn compute_layer(key: &str) -> usize {
    let hash = sha256(key.as_bytes());
    let mut layer = 0;
    for &b in &hash {
        if b < 64 {
            layer += 1;
        } else {
            return layer;
        }
        if b < 16 {
            layer += 1;
        } else {
            return layer;
        }
        if b < 4 {
            layer += 1;
        } else {
            return layer;
        }
        if b == 0 {
            layer += 1;
        } else {
            return layer;
        }
    }
    layer
}

/// Returns the number of leading bytes shared between two strings.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// An entry with its computed layer.
struct KeyEntry {
    key: String,
    value_cid: Cid,
    layer: usize,
}

/// An entry within an MST node.
struct NodeEntry {
    prefix_len: usize,
    key_suffix: String,
    value_cid: Cid,
    right_cid: Option<Cid>,
}

/// Result of building an MST: all generated blocks and the root CID.
pub struct MstResult {
    /// DAG-CBOR blocks: `(bytes, cid)` for each MST node.
    pub blocks: Vec<(Vec<u8>, Cid)>,
    /// Root CID of the tree.
    pub root: Cid,
}

/// Builds an MST from sorted `(path, record_cid)` entries.
///
/// Entries **must** be sorted lexicographically by path.
/// Returns all MST node blocks and the root CID.
pub fn build(entries: &[(String, Cid)]) -> MstResult {
    let mut blocks = Vec::new();

    if entries.is_empty() {
        // Empty tree: a node with no entries and no left pointer
        let node_bytes = encode_node(None, &[]);
        let root = Cid::for_cbor(&node_bytes);
        blocks.push((node_bytes, root.clone()));
        return MstResult { blocks, root };
    }

    // Compute layers
    let key_entries: Vec<KeyEntry> = entries
        .iter()
        .map(|(key, cid)| KeyEntry {
            key: key.clone(),
            value_cid: cid.clone(),
            layer: compute_layer(key),
        })
        .collect();

    let max_layer = key_entries.iter().map(|e| e.layer).max().unwrap_or(0);

    let root = build_recursive(&key_entries, max_layer, &mut blocks);
    MstResult { blocks, root }
}

/// Recursively builds the MST, returning the node CID.
fn build_recursive(entries: &[KeyEntry], layer: usize, blocks: &mut Vec<(Vec<u8>, Cid)>) -> Cid {
    if entries.is_empty() {
        // Empty subtree — encode an empty node
        let node_bytes = encode_node(None, &[]);
        let cid = Cid::for_cbor(&node_bytes);
        blocks.push((node_bytes, cid.clone()));
        return cid;
    }

    // Find the effective max layer for this set of entries
    let max_entry_layer = entries.iter().map(|e| e.layer).max().unwrap_or(0);
    let effective_layer = layer.min(max_entry_layer);

    // Partition: entries at this layer become node entries,
    // entries below this layer form subtrees between them
    let mut at_layer: Vec<&KeyEntry> = Vec::new();
    let mut groups: Vec<Vec<&KeyEntry>> = vec![vec![]];

    for entry in entries {
        if entry.layer == effective_layer {
            at_layer.push(entry);
            groups.push(vec![]);
        } else {
            // Safety: groups always has at least one element
            #[allow(clippy::unwrap_used)]
            groups.last_mut().unwrap().push(entry);
        }
    }

    // If all entries are at this layer (common for small repos), build a flat node
    // Build left subtree from entries before the first node entry
    let left_cid = if !groups[0].is_empty() && effective_layer > 0 {
        let sub: Vec<KeyEntry> = groups[0].iter().map(|e| clone_entry(e)).collect();
        Some(build_recursive(&sub, effective_layer - 1, blocks))
    } else {
        None
    };

    // Build node entries with right subtrees
    let mut node_entries = Vec::new();
    let mut prev_key = "";

    for (i, entry) in at_layer.iter().enumerate() {
        let right_cid = if !groups[i + 1].is_empty() && effective_layer > 0 {
            let sub: Vec<KeyEntry> = groups[i + 1].iter().map(|e| clone_entry(e)).collect();
            Some(build_recursive(&sub, effective_layer - 1, blocks))
        } else {
            None
        };

        let prefix_len = common_prefix_len(prev_key, &entry.key);
        let key_suffix = entry.key[prefix_len..].to_string();

        node_entries.push(NodeEntry {
            prefix_len,
            key_suffix,
            value_cid: entry.value_cid.clone(),
            right_cid,
        });

        prev_key = &entry.key;
    }

    let node_bytes = encode_node(left_cid.as_ref(), &node_entries);
    let node_cid = Cid::for_cbor(&node_bytes);
    blocks.push((node_bytes, node_cid.clone()));
    node_cid
}

fn clone_entry(e: &&KeyEntry) -> KeyEntry {
    KeyEntry {
        key: e.key.clone(),
        value_cid: e.value_cid.clone(),
        layer: e.layer,
    }
}

/// Encodes an MST node as DAG-CBOR.
///
/// DAG-CBOR map keys are sorted by encoded byte length, then lexicographically.
/// Node keys: "e" (1 char), "l" (1 char) — sorted: "e", "l"
/// Entry keys: "k" (1 char), "p" (1 char), "t" (1 char), "v" (1 char) — sorted: "k", "p", "t", "v"
///
/// Null CID fields (`l`, `t`) are **omitted** (matching the Go reference implementation).
#[allow(clippy::unwrap_used)]
fn encode_node(left_cid: Option<&Cid>, entries: &[NodeEntry]) -> Vec<u8> {
    let cbor_entries: Vec<CborValue> = entries
        .iter()
        .map(|e| {
            // Keys sorted: k, p, t, v
            let mut fields = vec![
                (
                    CborValue::Text("k".to_string()),
                    CborValue::Bytes(e.key_suffix.as_bytes().to_vec()),
                ),
                (
                    CborValue::Text("p".to_string()),
                    CborValue::Integer((e.prefix_len as i64).into()),
                ),
            ];

            if let Some(ref right) = e.right_cid {
                fields.push((CborValue::Text("t".to_string()), cid_link(right)));
            }

            fields.push((CborValue::Text("v".to_string()), cid_link(&e.value_cid)));

            CborValue::Map(fields)
        })
        .collect();

    // Node keys sorted: "e", "l"
    let mut node_fields = vec![(
        CborValue::Text("e".to_string()),
        CborValue::Array(cbor_entries),
    )];

    if let Some(left) = left_cid {
        node_fields.push((CborValue::Text("l".to_string()), cid_link(left)));
    }

    let node = CborValue::Map(node_fields);
    let mut bytes = Vec::new();
    ciborium::into_writer(&node, &mut bytes).unwrap();
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_layer() {
        // Most random keys should be layer 0
        assert_eq!(compute_layer("app.bsky.feed.post/abc"), 0);
        // Test that compute_layer returns a reasonable value
        let layer = compute_layer("test-key");
        assert!(layer < 128, "layer should be reasonable");
    }

    #[test]
    fn test_common_prefix_len() {
        assert_eq!(common_prefix_len("abc", "abd"), 2);
        assert_eq!(common_prefix_len("abc", "xyz"), 0);
        assert_eq!(common_prefix_len("abc", "abc"), 3);
        assert_eq!(common_prefix_len("", "abc"), 0);
    }

    #[test]
    fn test_empty_mst() {
        let result = build(&[]);
        assert_eq!(result.blocks.len(), 1);
        // Root should exist
        assert!(!result.root.to_bytes().is_empty());
    }

    #[test]
    fn test_single_entry_mst() {
        let cid = Cid::for_cbor(b"test record data");
        let entries = vec![("app.bsky.feed.post/abc123".to_string(), cid.clone())];
        let result = build(&entries);

        assert!(!result.blocks.is_empty());
        // Verify root CID matches the one block we generated
        let root_block = result.blocks.last().unwrap();
        assert_eq!(root_block.1, result.root);
    }

    #[test]
    fn test_multiple_entries_mst() {
        let entries: Vec<(String, Cid)> = (0..10)
            .map(|i| {
                let key = format!("app.bsky.feed.post/rec{i:04}");
                let cid = Cid::for_cbor(format!("record data {i}").as_bytes());
                (key, cid)
            })
            .collect();

        let result = build(&entries);
        assert!(!result.blocks.is_empty());
        // All blocks should be valid DAG-CBOR
        for (bytes, cid) in &result.blocks {
            assert_eq!(*cid, Cid::for_cbor(bytes));
        }
    }

    #[test]
    fn test_entries_must_be_sorted() {
        let cid1 = Cid::for_cbor(b"data1");
        let cid2 = Cid::for_cbor(b"data2");
        let cid3 = Cid::for_cbor(b"data3");

        // Sorted entries
        let entries = vec![
            ("a/1".to_string(), cid1.clone()),
            ("b/2".to_string(), cid2.clone()),
            ("c/3".to_string(), cid3.clone()),
        ];
        let result = build(&entries);
        assert!(!result.blocks.is_empty());
    }

    #[test]
    fn test_mst_deterministic() {
        let entries: Vec<(String, Cid)> = (0..5)
            .map(|i| {
                let key = format!("col/key{i}");
                let cid = Cid::for_cbor(format!("val{i}").as_bytes());
                (key, cid)
            })
            .collect();

        let result1 = build(&entries);
        let result2 = build(&entries);
        assert_eq!(result1.root, result2.root);
    }
}
