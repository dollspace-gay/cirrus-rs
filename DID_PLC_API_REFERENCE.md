# did:plc Directory API Reference

Complete API documentation for the PLC Directory service.

---

## Base URL

**Default**: `https://plc.directory`

**Alternative instances**: Any compatible PLC directory implementation

---

## 1. Create/Update DID Operation

### Endpoint
```
POST /{did}
```

### Description
Submit a signed operation to create or update a DID on the directory.

### Request Headers
```
Content-Type: application/json
```

### Request Body
Signed PLC operation object (JSON):

```json
{
  "type": "plc_operation",
  "rotationKeys": ["did:key:...", "did:key:..."],
  "verificationMethods": {
    "atproto": "did:key:..."
  },
  "alsoKnownAs": ["at://handle.example.com"],
  "services": {
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"
    }
  },
  "prev": null,
  "sig": "base64url_encoded_signature"
}
```

For updates, `prev` should be the CID of the previous operation.

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | Operation accepted and stored |
| 400 | Bad request (invalid JSON, too large, invalid algorithm) |
| 409 | Conflict (signature validation failed, recovery rules violated) |
| 500 | Server error |

### Response Body (Success)
```json
{}
```

### Response Body (Error)
```json
{
  "error": "description of validation failure"
}
```

### Examples

#### Create Genesis Operation
```bash
curl -X POST https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6 \
  -H "Content-Type: application/json" \
  -d '{
    "type": "plc_operation",
    "rotationKeys": [
      "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4"
    ],
    "verificationMethods": {
      "atproto": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
    },
    "alsoKnownAs": [
      "at://alice.example.com"
    ],
    "services": {
      "atproto_pds": {
        "type": "AtprotoPersonalDataServer",
        "endpoint": "https://pds.example.com"
      }
    },
    "prev": null,
    "sig": "ICjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
  }'
```

#### Update Operation (Key Rotation)
```bash
curl -X POST https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6 \
  -H "Content-Type: application/json" \
  -d '{
    "type": "plc_operation",
    "rotationKeys": [
      "did:key:zk3ttaaBzjMupzBVJGgf3BpKvL5LdhYZqYy8G7AXQfHjW5Hh9",
      "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4"
    ],
    "verificationMethods": {
      "atproto": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
    },
    "alsoKnownAs": [
      "at://alice.example.com"
    ],
    "services": {
      "atproto_pds": {
        "type": "AtprotoPersonalDataServer",
        "endpoint": "https://pds.example.com"
      }
    },
    "prev": "bafyreigltznq3w3g2btjmqr54vjxib37zw73kmjxpzf2s4zzwwwl5mqcq",
    "sig": "KCjLCQn-u8cOplJ--q1jKMq4ypqQw8Xl_EZFsJDFbO7vGhXzCMp3aPrJrUAGLv7nFNjxE-v4-aGd-EwqLGJNEw"
  }'
```

---

## 2. Resolve DID Document

### Endpoint
```
GET /{did}
```

### Description
Resolve a DID to its W3C DID Document representation.

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | DID found, document returned |
| 404 | DID not found |
| 500 | Server error |

### Response Body

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1",
    "https://w3id.org/security/suites/ecdsa-2019/v1"
  ],
  "id": "did:plc:7iza6de2dwap2sbkpav7c6c6",
  "alsoKnownAs": [
    "at://alice.example.com"
  ],
  "verificationMethod": [
    {
      "id": "#atproto",
      "type": "Multikey",
      "controller": "did:plc:7iza6de2dwap2sbkpav7c6c6",
      "publicKeyMultibase": "z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
    }
  ],
  "service": [
    {
      "id": "#atproto_pds",
      "type": "AtprotoPersonalDataServer",
      "serviceEndpoint": "https://pds.example.com"
    }
  ]
}
```

### Examples

```bash
# Resolve DID to DID Document
curl https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6

# Pretty-print response
curl -s https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6 | jq .
```

---

## 3. Resolve DID State Data

### Endpoint
```
GET /{did}/data
```

### Description
Get the current PLC state data for a DID (not in W3C DID Document format).

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | DID found, state data returned |
| 404 | DID not found |
| 500 | Server error |

### Response Body

```json
{
  "did": "did:plc:7iza6de2dwap2sbkpav7c6c6",
  "rotationKeys": [
    "did:key:zk3ttpk3ppKyQrjqQvB8L6qWRwWaVz8tdPx5yqrP7QZDZvzt4",
    "did:key:zk3ttaaBzjMupzBVJGgf3BpKvL5LdhYZqYy8G7AXQfHjW5Hh9"
  ],
  "verificationMethods": {
    "atproto": "did:key:z521wZeJfY92p3TZLjL3cLSKAGaJQBWCCN9HZ88xw8nnXz9AX"
  },
  "alsoKnownAs": [
    "at://alice.example.com"
  ],
  "services": {
    "atproto_pds": {
      "type": "AtprotoPersonalDataServer",
      "endpoint": "https://pds.example.com"
    }
  }
}
```

### Examples

```bash
# Get raw state data
curl https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6/data

# Extract just rotation keys
curl -s https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6/data | jq '.rotationKeys'
```

---

## 4. Get Audit Log

### Endpoint
```
GET /{did}/log/audit
```

### Description
Retrieve the complete audit log of all operations for a DID.

### Query Parameters
None

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | Audit log returned |
| 404 | DID not found |
| 500 | Server error |

### Response Body

Array of audit entries:

```json
[
  {
    "cid": "bafyreigltznq3w3g2btjmqr54vjxib37zw73kmjxpzf2s4zzwwwl5mqcq",
    "operation": {
      "type": "plc_operation",
      "rotationKeys": ["did:key:..."],
      "verificationMethods": {"atproto": "did:key:..."},
      "alsoKnownAs": ["at://alice.example.com"],
      "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example.com"}},
      "prev": null,
      "sig": "..."
    },
    "createdAt": "2025-02-16T21:00:00.000Z",
    "nullified": false
  },
  {
    "cid": "bafyreiabcd1234567890abcdef1234567890abcdef1234567890abcdef",
    "operation": {
      "type": "plc_operation",
      "rotationKeys": ["did:key:...", "did:key:..."],
      "verificationMethods": {"atproto": "did:key:..."},
      "alsoKnownAs": ["at://alice.example.com"],
      "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example.com"}},
      "prev": "bafyreigltznq3w3g2btjmqr54vjxib37zw73kmjxpzf2s4zzwwwl5mqcq",
      "sig": "..."
    },
    "createdAt": "2025-02-17T10:30:00.000Z",
    "nullified": false
  }
]
```

### Examples

```bash
# Get full audit log
curl https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6/log/audit

# Get latest operation CID
curl -s https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6/log/audit | jq '.[-1].cid'

# Count total operations
curl -s https://plc.directory/did:plc:7iza6de2dwap2sbkpav7c6c6/log/audit | jq 'length'
```

---

## 5. Bulk Export

### Endpoint
```
GET /export
```

### Description
Export all operations from the directory in paginated JSON lines format.

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `count` | integer | No | Number of entries per page (max 1000, default varies) |
| `after` | string/integer | No | Cursor for pagination; integer (seq) or timestamp |

### Response Codes

| Code | Meaning |
|------|---------|
| 200 | Results returned |
| 400 | Invalid query parameters |
| 500 | Server error |

### Response Body

JSON Lines format (one JSON object per line). Each entry has the following fields:

#### With Sequence Number Cursor (after=0 or after=<seq>)

```
{"type":"sequenced_op","operation":{...},"did":"did:plc:...","cid":"bafyrei...","createdAt":"2025-02-16T21:00:00.000Z","seq":1}
{"type":"sequenced_op","operation":{...},"did":"did:plc:...","cid":"bafyrei...","createdAt":"2025-02-16T21:01:00.000Z","seq":2}
{"type":"sequenced_op","operation":{...},"did":"did:plc:...","cid":"bafyrei...","createdAt":"2025-02-16T21:02:00.000Z","seq":3}
```

Fields:
- `type` (string): Always `"sequenced_op"`
- `operation` (object): The PLC operation
- `did` (string): The DID identifier
- `cid` (string): Content identifier (CID) of the operation
- `createdAt` (string): ISO 8601 timestamp when accepted
- `seq` (integer): Monotonically increasing sequence number

#### Legacy Format (after=<timestamp> or no after parameter)

```
{"operation":{...},"did":"did:plc:...","cid":"bafyrei...","createdAt":"2025-02-16T21:00:00.000Z","nullified":false}
{"operation":{...},"did":"did:plc:...","cid":"bafyrei...","createdAt":"2025-02-16T21:01:00.000Z","nullified":false}
```

Fields:
- `operation` (object): The PLC operation
- `did` (string): The DID identifier
- `cid` (string): Content identifier (CID) of the operation
- `createdAt` (string): ISO 8601 timestamp when accepted
- `nullified` (boolean): Whether operation was invalidated by recovery

### Examples

```bash
# Get first page (legacy format)
curl 'https://plc.directory/export?count=100'

# Get first page (sequence number format - recommended)
curl 'https://plc.directory/export?count=100&after=0'

# Get next page using sequence number
curl 'https://plc.directory/export?count=100&after=150'

# Get page by timestamp (legacy)
curl 'https://plc.directory/export?count=100&after=2025-02-16T21:00:00.000Z'

# Process all operations with jq
curl -s 'https://plc.directory/export?count=1000&after=0' | \
  jq 'select(.type=="sequenced_op") | {did, seq}'
```

### Pagination Pattern

```rust
// Example: Iterate through all operations
let mut cursor = 0;
loop {
    let url = format!(
        "https://plc.directory/export?count=1000&after={}",
        cursor
    );

    let response: Vec<ExportEntry> = reqwest::Client::new()
        .get(&url)
        .send()
        .await?
        .json()
        .await?;

    if response.is_empty() {
        break;
    }

    for entry in &response {
        process_operation(&entry.operation)?;
    }

    cursor = response.last().unwrap().seq;
}
```

---

## 6. Export WebSocket Stream

### Endpoint
```
WebSocket wss://plc.directory/export/stream
```

### Description
Real-time stream of newly accepted operations and historical catch-up.

### Connection Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `cursor` | integer | Optional; sequence number to start from (for catch-up) |

### Response Format

Stream of JSON objects (delimited by WebSocket message frames, not newlines):

```json
{
  "type": "sequenced_op",
  "operation": {...},
  "did": "did:plc:...",
  "cid": "bafyrei...",
  "createdAt": "2025-02-16T21:00:00.000Z",
  "seq": 12345
}
```

### Close Codes

The server may close the connection with a reason string:

| Reason | Meaning |
|--------|---------|
| `FutureCursor` | Cursor value is higher than current sequence |
| `OutdatedCursor` | Cursor is too old (before catch-up window, typically 7 days) |
| `ConsumerTooSlow` | Client not receiving messages fast enough |

### Examples

```typescript
// TypeScript/JavaScript example
const socket = new WebSocket('wss://plc.directory/export/stream?cursor=10000');

socket.onmessage = (event) => {
  const entry = JSON.parse(event.data);
  console.log(`Operation ${entry.seq}: ${entry.did}`);
};

socket.onclose = (event) => {
  console.log(`Connection closed: ${event.reason}`);
};
```

```rust
// Rust example with tokio-tungstenite
use tokio_tungstenite::connect_async;

#[tokio::main]
async fn main() {
    let url = "wss://plc.directory/export/stream?cursor=0";
    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");

    let (_, mut read) = ws_stream.split();

    while let Some(msg) = read.next().await {
        let msg = msg.expect("Failed to receive");
        let json: serde_json::Value = serde_json::from_str(&msg.to_string())?;
        println!("Received operation seq={}", json["seq"]);
    }
}
```

---

## 7. Error Responses

### Standard Error Format

All error responses return JSON with the following structure:

```json
{
  "error": "Descriptive error message"
}
```

### HTTP Status Codes

| Status | Meaning | Common Cause |
|--------|---------|--------------|
| 400 | Bad Request | Malformed JSON, invalid parameters, operation too large |
| 404 | Not Found | DID doesn't exist, invalid endpoint |
| 409 | Conflict | Signature validation failed, recovery rules violated, rotation window expired |
| 500 | Internal Server Error | PLC server bug or issue |
| 503 | Service Unavailable | PLC server maintenance or overload |

### Example Errors

```bash
# Invalid signature
curl -X POST https://plc.directory/did:plc:test \
  -H "Content-Type: application/json" \
  -d '{"type":"plc_operation","rotationKeys":[],...}'

# Response:
# 409 Conflict
# {"error":"signature verification failed"}

# DID not found
curl https://plc.directory/did:plc:nonexistent

# Response:
# 404 Not Found
# {}  (or similar)

# Operation too large
# 400 Bad Request
# {"error":"operation exceeds maximum size of 7500 bytes"}
```

---

## 8. Rate Limiting

The PLC directory may enforce rate limits on requests.

### Current Policy
- **Limits**: Generous per-IP rate limiting (specific numbers not published)
- **Headers**: May include standard rate limit headers (not guaranteed)
- **Behavior**: Returns 429 Too Many Requests if exceeded

### Best Practices
- Implement exponential backoff for retries
- Use `/export/stream` for real-time updates instead of polling
- Cache DID documents locally when possible
- Batch operations when multiple creates/updates needed

---

## 9. CORS Policy

The PLC directory supports CORS requests from browsers.

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

---

## 10. Content-Type Handling

### Request
- Expects: `application/json`
- Will reject other content types

### Response
- Returns: `application/json` for all responses
- Returns: Streaming JSON lines for `/export` endpoint

---

## 11. Complete Workflow Example

```bash
#!/bin/bash

DIRECTORY="https://plc.directory"
DID="did:plc:example123456789abcdefgh"

# 1. Create a DID
echo "Creating DID..."
curl -X POST "$DIRECTORY/$DID" \
  -H "Content-Type: application/json" \
  -d @genesis_operation.json

# 2. Resolve DID document
echo "Resolving DID document..."
curl "$DIRECTORY/$DID" | jq .

# 3. Get current state data
echo "Getting state data..."
curl "$DIRECTORY/$DID/data" | jq .

# 4. Get audit log
echo "Getting audit log..."
curl "$DIRECTORY/$DID/log/audit" | jq '.[] | {cid, createdAt, nullified}'

# 5. Submit update operation
echo "Updating DID..."
curl -X POST "$DIRECTORY/$DID" \
  -H "Content-Type: application/json" \
  -d @update_operation.json

# 6. Verify update in audit log
echo "Verifying update..."
curl "$DIRECTORY/$DID/log/audit" | jq '.[-1]'

# 7. Export recent operations
echo "Exporting recent operations..."
curl "https://plc.directory/export?count=10&after=0" | jq '.[] | {did, seq}'
```

---

## 12. Troubleshooting

### "409 Conflict" on Create

**Cause**: DID already exists or signature invalid

**Solutions**:
- Use different DID identifier
- Verify signature is correctly encoded (base64url, no padding)
- Ensure signature is "low-S" canonical form
- Check private key matches public key in rotationKeys

### "409 Conflict" on Update

**Cause**: Signature doesn't match rotation key or recovery rules violated

**Solutions**:
- Verify `prev` field matches latest operation CID
- Ensure signing with correct rotation key
- Check recovery window (72 hours) for recovery operations
- Verify key authority ordering for recovery

### "404 Not Found"

**Cause**: DID doesn't exist or not yet propagated

**Solutions**:
- Verify DID identifier is correctly formatted
- Wait a few seconds after creation before querying
- Check audit log exists: `GET /{did}/log/audit`

### Slow Responses

**Cause**: Large audit logs, network latency, server load

**Solutions**:
- Use `/data` endpoint instead of full document
- Cache results locally
- Consider running a mirror/replica
- Use exponential backoff on retries

---

## 13. API Client Libraries

Official and community implementations:

- **Node.js**: `@atcute/crypto`, `did-method-key`
- **Python**: `did-plc` (community)
- **Go**: `did-method-plc-go` (community)
- **Rust**: Multiple implementations in atproto ecosystem

---

**Last Updated**: February 16, 2026

**Specification Version**: v0.3.0

**Official Spec**: https://web.plc.directory/spec/v0.1/did-plc

