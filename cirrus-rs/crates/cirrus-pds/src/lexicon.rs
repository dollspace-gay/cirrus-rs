//! Lexicon schema loading and validation.
//!
//! AT Protocol uses Lexicons to define data schemas for records and XRPC methods.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{PdsError, Result};

/// Lexicon document version.
pub const LEXICON_VERSION: u32 = 1;

/// A Lexicon document defining schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexiconDoc {
    /// Lexicon version (always 1).
    pub lexicon: u32,
    /// NSID of this lexicon.
    pub id: String,
    /// Revision number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Definitions in this lexicon.
    pub defs: HashMap<String, LexiconDef>,
}

/// A single definition within a lexicon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LexiconDef {
    /// Record type definition.
    Record(RecordDef),
    /// Query (GET) procedure.
    Query(QueryDef),
    /// Procedure (POST) method.
    Procedure(ProcedureDef),
    /// Subscription (WebSocket) method.
    Subscription(SubscriptionDef),
    /// Object type.
    Object(ObjectDef),
    /// Token (enum-like) type.
    Token(TokenDef),
    /// Array type.
    Array(ArrayDef),
    /// String type.
    String(StringDef),
    /// Blob type.
    Blob(BlobDef),
    /// Union type.
    #[serde(rename = "union")]
    Union(UnionDef),
}

/// Record type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Record key type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Record schema.
    pub record: ObjectSchema,
}

/// Query (GET) method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Query parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ObjectSchema>,
    /// Output schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputSchema>,
    /// Possible errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ErrorDef>>,
}

/// Procedure (POST) method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Input schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<InputSchema>,
    /// Output schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<OutputSchema>,
    /// Possible errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ErrorDef>>,
}

/// Subscription (WebSocket) method definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<ObjectSchema>,
    /// Message schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageSchema>,
    /// Possible errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<ErrorDef>>,
}

/// Object type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Required properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    /// Nullable properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<Vec<String>>,
    /// Property definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, PropertySchema>>,
}

/// Token (enum-like) definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Array type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Item schema.
    pub items: Box<PropertySchema>,
    /// Minimum items.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum items.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
}

/// String type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Format (e.g., "at-uri", "did", "handle").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Minimum length.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum length.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// Maximum byte length (for graphemes).
    #[serde(rename = "maxGraphemes", skip_serializing_if = "Option::is_none")]
    pub max_graphemes: Option<u32>,
    /// Known values (enum).
    #[serde(rename = "knownValues", skip_serializing_if = "Option::is_none")]
    pub known_values: Option<Vec<String>>,
    /// Allowed values (strict enum).
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// Constant value.
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<String>,
    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// Blob type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Accepted MIME types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,
    /// Maximum size in bytes.
    #[serde(rename = "maxSize", skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

/// Union type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionDef {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// References to allowed types.
    pub refs: Vec<String>,
    /// Whether union is closed (no other types allowed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
}

/// Object schema for records and parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSchema {
    /// Type (always "object").
    #[serde(rename = "type")]
    pub schema_type: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Required properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    /// Nullable properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<Vec<String>>,
    /// Property definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, PropertySchema>>,
}

/// Property schema (can be various types).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PropertySchema {
    /// String property.
    String(StringProp),
    /// Integer property.
    Integer(IntegerProp),
    /// Boolean property.
    Boolean(BooleanProp),
    /// Unknown/generic property.
    Unknown(UnknownProp),
    /// Array property.
    Array(ArrayProp),
    /// Object property.
    Object(ObjectProp),
    /// Reference to another definition.
    Ref(RefProp),
    /// Union of types.
    Union(UnionProp),
    /// Blob property.
    Blob(BlobProp),
    /// Bytes property.
    Bytes(BytesProp),
    /// CID link property.
    #[serde(rename = "cid-link")]
    CidLink(CidLinkProp),
}

/// String property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Minimum length.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum length.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// Maximum graphemes.
    #[serde(rename = "maxGraphemes", skip_serializing_if = "Option::is_none")]
    pub max_graphemes: Option<u32>,
    /// Known values.
    #[serde(rename = "knownValues", skip_serializing_if = "Option::is_none")]
    pub known_values: Option<Vec<String>>,
    /// Enum values.
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    /// Constant.
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<String>,
    /// Default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// Integer property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegerProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Minimum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<i64>,
    /// Maximum value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<i64>,
    /// Enum values.
    #[serde(rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<i64>>,
    /// Default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<i64>,
}

/// Boolean property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
    /// Constant.
    #[serde(rename = "const", skip_serializing_if = "Option::is_none")]
    pub const_value: Option<bool>,
}

/// Unknown property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Array property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArrayProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Items schema.
    pub items: Box<PropertySchema>,
    /// Minimum length.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum length.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
}

/// Object property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Required properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    /// Nullable properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nullable: Option<Vec<String>>,
    /// Property definitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, PropertySchema>>,
}

/// Reference property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefProp {
    /// Reference target.
    #[serde(rename = "ref")]
    pub ref_target: String,
}

/// Union property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnionProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// References.
    pub refs: Vec<String>,
    /// Closed union.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed: Option<bool>,
}

/// Blob property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Accepted MIME types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<Vec<String>>,
    /// Maximum size.
    #[serde(rename = "maxSize", skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
}

/// Bytes property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Minimum length.
    #[serde(rename = "minLength", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    /// Maximum length.
    #[serde(rename = "maxLength", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
}

/// CID link property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidLinkProp {
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Input schema for procedures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSchema {
    /// Encoding (e.g., "application/json").
    pub encoding: String,
    /// Schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<ObjectSchema>,
}

/// Output schema for methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSchema {
    /// Encoding.
    pub encoding: String,
    /// Schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<ObjectSchema>,
}

/// Message schema for subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSchema {
    /// Schema (union of message types).
    pub schema: UnionProp,
}

/// Error definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDef {
    /// Error name.
    pub name: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Lexicon schema store.
pub struct LexiconStore {
    lexicons: HashMap<String, LexiconDoc>,
}

impl Default for LexiconStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LexiconStore {
    /// Creates a new empty lexicon store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lexicons: HashMap::new(),
        }
    }

    /// Loads a lexicon from JSON.
    ///
    /// # Errors
    /// Returns an error if parsing fails.
    pub fn load_json(&mut self, json: &str) -> Result<()> {
        let doc: LexiconDoc =
            serde_json::from_str(json).map_err(|e| PdsError::Lexicon(format!("parse error: {e}")))?;

        if doc.lexicon != LEXICON_VERSION {
            return Err(PdsError::Lexicon(format!(
                "unsupported lexicon version: {}",
                doc.lexicon
            )));
        }

        self.lexicons.insert(doc.id.clone(), doc);
        Ok(())
    }

    /// Gets a lexicon by NSID.
    #[must_use]
    pub fn get(&self, nsid: &str) -> Option<&LexiconDoc> {
        self.lexicons.get(nsid)
    }

    /// Gets a definition from a lexicon.
    #[must_use]
    pub fn get_def(&self, nsid: &str, def_name: &str) -> Option<&LexiconDef> {
        self.lexicons.get(nsid).and_then(|doc| doc.defs.get(def_name))
    }

    /// Gets the main definition from a lexicon.
    #[must_use]
    pub fn get_main(&self, nsid: &str) -> Option<&LexiconDef> {
        self.get_def(nsid, "main")
    }

    /// Returns all loaded NSIDs.
    #[must_use]
    pub fn nsids(&self) -> Vec<&str> {
        self.lexicons.keys().map(String::as_str).collect()
    }

    /// Returns the number of loaded lexicons.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lexicons.len()
    }

    /// Returns true if no lexicons are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lexicons.is_empty()
    }

    /// Validates a record value against its lexicon schema.
    ///
    /// # Errors
    /// Returns an error if validation fails.
    pub fn validate_record(
        &self,
        collection: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        let def = self.get_main(collection).ok_or_else(|| {
            PdsError::Lexicon(format!("unknown collection: {collection}"))
        })?;

        match def {
            LexiconDef::Record(record) => self.validate_object(value, &record.record),
            _ => Err(PdsError::Lexicon(format!(
                "{collection} is not a record type"
            ))),
        }
    }

    fn validate_object(&self, value: &serde_json::Value, schema: &ObjectSchema) -> Result<()> {
        let obj = value.as_object().ok_or_else(|| {
            PdsError::Lexicon("expected object".into())
        })?;

        // Check required properties
        if let Some(required) = &schema.required {
            for prop in required {
                if !obj.contains_key(prop) {
                    return Err(PdsError::Lexicon(format!("missing required property: {prop}")));
                }
            }
        }

        // Validate each property
        if let Some(properties) = &schema.properties {
            for (key, prop_schema) in properties {
                if let Some(prop_value) = obj.get(key) {
                    self.validate_property(prop_value, prop_schema)?;
                }
            }
        }

        Ok(())
    }

    fn validate_property(&self, value: &serde_json::Value, schema: &PropertySchema) -> Result<()> {
        match schema {
            PropertySchema::String(s) => Self::validate_string(value, s),
            PropertySchema::Integer(i) => Self::validate_integer(value, i),
            PropertySchema::Boolean(_) => {
                if !value.is_boolean() {
                    return Err(PdsError::Lexicon("expected boolean".into()));
                }
                Ok(())
            }
            PropertySchema::Array(a) => self.validate_array(value, a),
            PropertySchema::Object(o) => {
                let schema = ObjectSchema {
                    schema_type: "object".to_string(),
                    description: o.description.clone(),
                    required: o.required.clone(),
                    nullable: o.nullable.clone(),
                    properties: o.properties.clone(),
                };
                self.validate_object(value, &schema)
            }
            // Accept any value for complex types that require full lexicon resolution
            PropertySchema::Unknown(_)
            | PropertySchema::Blob(_)
            | PropertySchema::Bytes(_)
            | PropertySchema::CidLink(_)
            | PropertySchema::Ref(_)
            | PropertySchema::Union(_) => Ok(()),
        }
    }

    fn validate_string(value: &serde_json::Value, schema: &StringProp) -> Result<()> {
        let s = value.as_str().ok_or_else(|| {
            PdsError::Lexicon("expected string".into())
        })?;

        if let Some(min) = schema.min_length {
            if s.len() < min as usize {
                return Err(PdsError::Lexicon(format!(
                    "string too short (min: {min})"
                )));
            }
        }

        if let Some(max) = schema.max_length {
            if s.len() > max as usize {
                return Err(PdsError::Lexicon(format!(
                    "string too long (max: {max})"
                )));
            }
        }

        if let Some(enum_values) = &schema.enum_values {
            if !enum_values.contains(&s.to_string()) {
                return Err(PdsError::Lexicon(format!(
                    "invalid enum value: {s}"
                )));
            }
        }

        if let Some(const_value) = &schema.const_value {
            if s != const_value {
                return Err(PdsError::Lexicon(format!(
                    "expected const: {const_value}"
                )));
            }
        }

        // Validate format
        if let Some(format) = &schema.format {
            Self::validate_format(s, format)?;
        }

        Ok(())
    }

    fn validate_integer(value: &serde_json::Value, schema: &IntegerProp) -> Result<()> {
        let n = value.as_i64().ok_or_else(|| {
            PdsError::Lexicon("expected integer".into())
        })?;

        if let Some(min) = schema.minimum {
            if n < min {
                return Err(PdsError::Lexicon(format!(
                    "integer too small (min: {min})"
                )));
            }
        }

        if let Some(max) = schema.maximum {
            if n > max {
                return Err(PdsError::Lexicon(format!(
                    "integer too large (max: {max})"
                )));
            }
        }

        if let Some(enum_values) = &schema.enum_values {
            if !enum_values.contains(&n) {
                return Err(PdsError::Lexicon(format!(
                    "invalid enum value: {n}"
                )));
            }
        }

        Ok(())
    }

    fn validate_array(&self, value: &serde_json::Value, schema: &ArrayProp) -> Result<()> {
        let arr = value.as_array().ok_or_else(|| {
            PdsError::Lexicon("expected array".into())
        })?;

        if let Some(min) = schema.min_length {
            if arr.len() < min as usize {
                return Err(PdsError::Lexicon(format!(
                    "array too short (min: {min})"
                )));
            }
        }

        if let Some(max) = schema.max_length {
            if arr.len() > max as usize {
                return Err(PdsError::Lexicon(format!(
                    "array too long (max: {max})"
                )));
            }
        }

        for item in arr {
            self.validate_property(item, &schema.items)?;
        }

        Ok(())
    }

    fn validate_format(value: &str, format: &str) -> Result<()> {
        match format {
            "at-uri" => {
                if !value.starts_with("at://") {
                    return Err(PdsError::Lexicon("invalid at-uri format".into()));
                }
            }
            "did" => {
                if !value.starts_with("did:") {
                    return Err(PdsError::Lexicon("invalid did format".into()));
                }
            }
            "handle" => {
                if !value.contains('.') || value.starts_with('.') || value.ends_with('.') {
                    return Err(PdsError::Lexicon("invalid handle format".into()));
                }
            }
            "datetime" => {
                // ISO 8601 datetime
                if chrono::DateTime::parse_from_rfc3339(value).is_err() {
                    return Err(PdsError::Lexicon("invalid datetime format".into()));
                }
            }
            "uri" => {
                if url::Url::parse(value).is_err() {
                    return Err(PdsError::Lexicon("invalid uri format".into()));
                }
            }
            "cid" => {
                // CID format (base32 or base58)
                if !value.starts_with('b') && !value.starts_with('z') {
                    return Err(PdsError::Lexicon("invalid cid format".into()));
                }
            }
            "tid" => {
                // TID format (13 char base32-sort)
                if value.len() != 13 {
                    return Err(PdsError::Lexicon("invalid tid format".into()));
                }
            }
            // These formats have complex rules or are unknown - skip validation
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_lexicon() {
        let json = r#"{
            "lexicon": 1,
            "id": "app.bsky.feed.post",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text", "createdAt"],
                        "properties": {
                            "text": {
                                "type": "string",
                                "maxLength": 3000,
                                "maxGraphemes": 300
                            },
                            "createdAt": {
                                "type": "string",
                                "format": "datetime"
                            }
                        }
                    }
                }
            }
        }"#;

        let mut store = LexiconStore::new();
        store.load_json(json).unwrap();

        assert_eq!(store.len(), 1);
        assert!(store.get("app.bsky.feed.post").is_some());
        assert!(store.get_main("app.bsky.feed.post").is_some());
    }

    #[test]
    fn test_validate_record() {
        let json = r#"{
            "lexicon": 1,
            "id": "app.bsky.feed.post",
            "defs": {
                "main": {
                    "type": "record",
                    "key": "tid",
                    "record": {
                        "type": "object",
                        "required": ["text", "createdAt"],
                        "properties": {
                            "text": {
                                "type": "string",
                                "maxLength": 3000
                            },
                            "createdAt": {
                                "type": "string",
                                "format": "datetime"
                            }
                        }
                    }
                }
            }
        }"#;

        let mut store = LexiconStore::new();
        store.load_json(json).unwrap();

        // Valid record
        let valid = serde_json::json!({
            "text": "Hello world!",
            "createdAt": "2024-01-01T00:00:00.000Z"
        });
        assert!(store.validate_record("app.bsky.feed.post", &valid).is_ok());

        // Missing required field
        let invalid = serde_json::json!({
            "text": "Hello world!"
        });
        assert!(store.validate_record("app.bsky.feed.post", &invalid).is_err());
    }

    #[test]
    fn test_string_validation() {
        let json = r#"{
            "lexicon": 1,
            "id": "test.string",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["value"],
                        "properties": {
                            "value": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 10
                            }
                        }
                    }
                }
            }
        }"#;

        let mut store = LexiconStore::new();
        store.load_json(json).unwrap();

        // Valid
        let valid = serde_json::json!({"value": "hello"});
        assert!(store.validate_record("test.string", &valid).is_ok());

        // Too short
        let short = serde_json::json!({"value": ""});
        assert!(store.validate_record("test.string", &short).is_err());

        // Too long
        let long = serde_json::json!({"value": "hello world this is too long"});
        assert!(store.validate_record("test.string", &long).is_err());
    }

    #[test]
    fn test_format_validation() {
        // Valid formats
        assert!(LexiconStore::validate_format("at://did:plc:test/app.bsky.feed.post/123", "at-uri").is_ok());
        assert!(LexiconStore::validate_format("did:plc:test", "did").is_ok());
        assert!(LexiconStore::validate_format("user.bsky.social", "handle").is_ok());
        assert!(LexiconStore::validate_format("https://example.com", "uri").is_ok());
        assert!(LexiconStore::validate_format("2024-01-01T00:00:00.000Z", "datetime").is_ok());

        // Invalid formats
        assert!(LexiconStore::validate_format("not-an-at-uri", "at-uri").is_err());
        assert!(LexiconStore::validate_format("not-a-did", "did").is_err());
        assert!(LexiconStore::validate_format(".invalid", "handle").is_err());
    }
}
