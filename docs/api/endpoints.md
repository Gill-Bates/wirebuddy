# API Endpoints

Complete reference for WireBuddy REST API.

## Authentication

All endpoints require Bearer token authentication unless otherwise noted.

See [API Authentication](authentication.md) for details.

## Base URL

```
https://vpn.example.com/api
```

## Common Responses

### Success (200 OK)

```json
{
  "success": true,
  "data": { ... }
}
```

### Created (201 Created)

```json
{
  "success": true,
  "data": { ... },
  "message": "Resource created successfully"
}
```

### Error (4xx, 5xx)

```json
{
  "error": "Error Type",
  "message": "Detailed error message",
  "details": { ... }
}
```

## Interfaces

### List Interfaces

```
GET /api/wireguard/interfaces
```

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "name": "wg0",
      "address": "10.8.0.1/24",
      "listen_port": 51820,
      "status": "active",
      "peer_count": 12
    }
  ]
}
```

### Get Interface

```
GET /api/wireguard/interfaces/{name}
```

### Create Interface

```
POST /api/wireguard/interfaces
```

**Request:**

```json
{
  "name": "wg0",
  "address": "10.8.0.1/24",
  "listen_port": 51820,
  "dns": "1.1.1.1, 1.0.0.1"
}
```

### Update Interface

```
PUT /api/wireguard/interfaces/{name}
```

### Delete Interface

```
DELETE /api/wireguard/interfaces/{name}
```

### Start Interface

```
POST /api/wireguard/interfaces/{name}/start
```

### Stop Interface

```
POST /api/wireguard/interfaces/{name}/stop
```

## Peers

### List Peers

```
GET /api/wireguard/peers
```

**Query Parameters:**

- `interface` - Filter by interface name

**Response:**

```json
{
  "success": true,
  "data": [
    {
      "id": 12,
      "public_key": "base64publickey=",
      "name": "John's iPhone",
      "allowed_ips": "0.0.0.0/0, ::/0",
      "allowed_ips_mode": "full",
      "client_isolation": false,
      "peer_address": "10.13.13.2/32, fd13:13:13::2/128",
      "endpoint": null,
      "interface": "wg0",
      "is_enabled": true,
      "use_adblocker": true,
      "dns_logging_enabled": true,
      "blocklist_ids": ["ads", "adguard"],
      "created_at": "2026-03-23T12:00:00Z",
      "updated_at": "2026-03-23T12:00:00Z"
    }
  ]
}
```

### Get Peer

```
GET /api/wireguard/peers/{peer_id}
```

### Create Peer

```
POST /api/wireguard/peers
```

**Request:**

```json
{
  "name": "New Peer",
  "interface": "wg0",
  "allowed_ips": "0.0.0.0/0, ::/0",
  "allowed_ips_mode": "full",
  "use_adblocker": true,
  "dns_logging_enabled": true,
  "blocklist_ids": ["ads", "adguard"],
  "client_isolation": false
}
```

WireBuddy allocates `peer_address` automatically from the selected interface.

### Update Peer

```
PATCH /api/wireguard/peers/{peer_id}
```

The update endpoint accepts partial payloads. Example:

```json
{
  "allowed_ips_mode": "split",
  "use_adblocker": false,
  "client_isolation": true
}
```

### Delete Peer

```
DELETE /api/wireguard/peers/{peer_id}
```

### Get Peer Config

```
GET /api/wireguard/peers/{peer_id}/config
```

**Response:**

```
[Interface]
PrivateKey = <key>
Address = 10.8.0.2/32
DNS = 10.8.0.1

[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Generate QR Code

```
GET /api/wireguard/peers/{peer_id}/qrcode
```

Returns PNG image of QR code.

## Nodes

Node management endpoints for multi-node deployment. See [Multi-Node Deployment](../features/multi-node.md) for details.

!!! warning "Admin Only"
    All node endpoints require admin authentication.

### List Nodes

```
GET /api/nodes
```

**Response:**

```json
{
  "nodes": [
    {
      "id": "abc123def456",
      "name": "Frankfurt",
      "fqdn": "de.vpn.example.com",
      "wg_port": 51820,
      "status": "online",
      "last_seen": "2026-03-26T10:30:00Z",
      "enrolled_at": "2026-03-20T08:00:00Z",
      "created_at": "2026-03-20T08:00:00Z",
      "config_version": "3",
      "peers_count": 15
    }
  ]
}
```

**Status Values:**

- `pending` - Node created, awaiting enrollment
- `online` - Node enrolled and sending heartbeats
- `offline` - Heartbeat missed (>90s)
- `error` - Enrollment or sync error

### Get Node

```
GET /api/nodes/{node_id}
```

**Response:**

```json
{
  "id": "abc123def456",
  "name": "Frankfurt",
  "fqdn": "de.vpn.example.com",
  "wg_port": 51820,
  "status": "online",
  "last_seen": "2026-03-26T10:30:00Z",
  "enrolled_at": "2026-03-20T08:00:00Z",
  "cert_fingerprint": "SHA256:ab1cd2ef3...",
  "created_at": "2026-03-20T08:00:00Z",
  "config_version": "3",
  "metadata": null
}
```

### Create Node

```
POST /api/nodes
```

**Request:**

```json
{
  "name": "Frankfurt",
  "fqdn": "de.vpn.example.com",
  "wg_port": 51820
}
```

**Response:**

```json
{
  "node": {
    "id": "abc123def456",
    "name": "Frankfurt",
    "fqdn": "de.vpn.example.com",
    "wg_port": 51820,
    "status": "pending",
    "created_at": "2026-03-26T10:00:00Z"
  },
  "enrollment": {
    "token": "eyJub2RlX2lkIjoiYWJjMTIz...LmFiYzEyMw",
    "expires_at": "2026-03-27T10:00:00Z"
  }
}
```

**Error Responses:**

- `409 Conflict` — Name or FQDN already exists

!!! danger "Token Display"
    The enrollment token is shown **only once**. Store it securely.

### Update Node

```
PATCH /api/nodes/{node_id}
```

**Request:**

```json
{
  "name": "Frankfurt DC2",
  "fqdn": "de2.vpn.example.com",
  "wg_port": 51821
}
```

All fields are optional.

**Error Responses:**

- `404 Not Found` — Node does not exist
- `409 Conflict` — Name or FQDN already exists (on another node)

### Delete Node

```
DELETE /api/nodes/{node_id}
```

!!! warning "Peer Assignment"
    Peers assigned to the node will have their `node_id` unset (NULL). Update peer assignments before deletion.

### Regenerate Enrollment Token

```
POST /api/nodes/{node_id}/token
```

Invalidates the old token and generates a new one. Use when a node needs to re-enroll.

**Response:**

```json
{
  "token": "eyJub2RlX2lkIjoiYWJjMTIz...LmFiYzEyMw",
  "expires_at": "2026-03-27T10:00:00Z"
}
```

### Node Enrollment (Node → Master)

```
POST /api/nodes/enroll
```

!!! info "Authentication"
    Uses enrollment token in request body. Called by node daemon during initial setup.

**Request:**

```json
{
  "token": "eyJub2RlX2lkIjoiYWJjMTIz...",
  "cert_fingerprint": "SHA256:ab1cd2ef3..."
}
```

**Response:**

```json
{
  "node_id": "abc123def456",
  "api_secret": "generated_secret_for_future_auth"
}
```

### Node Heartbeat (Node → Master)

```
POST /api/nodes/{node_id}/heartbeat
```

!!! info "Authentication"
    Requires `Authorization: Bearer {api_secret}` header and `X-Client-Cert-Fingerprint` header.

**Request:**

```json
{
  "timestamp": "2026-03-26T10:30:00Z"
}
```

**Response:**

```json
{
  "status": "acknowledged"
}
```

### Get Node Config (Node → Master)

```
GET /api/nodes/{node_id}/config
```

!!! info "Authentication"
    Requires `Authorization: Bearer {api_secret}` header and `X-Client-Cert-Fingerprint` header.

Node pulls configuration changes from master.

**Response:**

```json
{
  "config_version": "3",
  "interfaces": [
    {
      "name": "wg0",
      "address": "10.8.0.1/24",
      "listen_port": 51820,
      "private_key": "encrypted_private_key",
      "public_key": "node_public_key",
      "peers": [
        {
          "public_key": "peer_public_key",
          "preshared_key": "peer_preshared_key",
          "allowed_ips": "10.8.0.2/32",
          "persistent_keepalive": 25
        }
      ]
    }
  ]
}
```

## DNS

### Get DNS Settings

```
GET /api/dns/settings
```

### Update DNS Settings

```
PUT /api/dns/settings
```

### Get Query Log

```
GET /api/dns/queries
```

**Query Parameters:**

- `client` - Filter by client name
- `domain` - Filter by domain
- `status` - allowed or blocked
- `limit` - Results per page (default: 100)
- `offset` - Pagination offset

### Get DNS Statistics

```
GET /api/dns/stats
```

### Get DNS Trend Data

```
GET /api/dns/trend
```

**Query Parameters:**

- `hours` - Time window in hours (1-8760, default: 24)
  - Examples: 168 (7d), 720 (30d), 2160 (90d), 4320 (180d), 8760 (1y)
- `bucket_minutes` - Data aggregation bucket size in minutes (5-10080, default: 60)
  - Auto-scaled based on time range for optimal performance
- `client_ips` - Optional comma-separated list of client IPs to filter by

**Implementation details:**

- Unfiltered requests use pre-aggregated DNS buckets from the TSDB
- Client-filtered requests are computed from raw JSONL query logs
- If no TSDB DNS data exists yet, the endpoint falls back to JSONL aggregation

**Response:**

```json
{
  "status": "ok",
  "data": {
    "hours": 168,
    "bucket_minutes": 1440,
    "labels": ["2026-03-25T00:00:00+00:00", "2026-03-26T00:00:00+00:00"],
    "total": [1234, 2345],
    "blocked": [123, 234],
    "block_rate": [10.0, 10.0]
  }
}
```

### Update Blocklists

```
POST /api/dns/blocklists/update
```

### Get Custom Rules

```
GET /api/dns/rules
```

### Add Custom Rule

```
POST /api/dns/rules
```

**Request:**

```json
{
  "action": "block",
  "domain": "ad.example.com",
  "client": "optional-peer-name"
}
```

## Metrics

### Get Dashboard Metrics

```
GET /api/metrics/dashboard
```

### Get Peer Traffic

```
GET /api/metrics/peers/{id}
```

**Query Parameters:**

- `start` - Start time (ISO 8601)
- `end` - End time (ISO 8601)
- `resolution` - hourly, daily, weekly

### Get Geographic Stats

```
GET /api/metrics/geo/countries
```

```
GET /api/metrics/geo/asn
```

## Users

### List Users (Admin Only)

```
GET /api/users
```

### Get User

```
GET /api/users/{id}
```

### Create User (Admin Only)

```
POST /api/users
```

**Request:**

```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "role": "user"
}
```

### Update User

```
PUT /api/users/{id}
```

### Delete User (Admin Only)

```
DELETE /api/users/{id}
```

## Settings

### Get Settings (Admin Only)

```
GET /api/settings
```

### Update Settings (Admin Only)

```
PUT /api/settings
```

## Speed Test

See [Speed Test Feature](../features/speedtest.md) for detailed documentation.

### Get Settings

```
GET /api/wireguard/speedtest/settings
```

**Response:**

```json
{
  "success": true,
  "data": {
    "enabled": true,
    "target": "auto",
    "servers": [
      {"id": "tele2", "name": "Tele2 (Europe)", "url": "http://speedtest.tele2.net/1GB.zip"},
      {"id": "cachefly", "name": "CacheFly (CDN)", "url": "http://cachefly.cachefly.net/100mb.test"},
      {"id": "thinkbroadband", "name": "ThinkBroadband (UK)", "url": "http://ipv4.download.thinkbroadband.com/100MB.zip"}
    ]
  }
}
```

### Update Settings (Admin Only)

```
PATCH /api/wireguard/speedtest/settings
```

**Request:**

```json
{
  "enabled": true,
  "target": "auto"
}
```

### Run Speed Test (Admin Only)

```
POST /api/wireguard/speedtest/run
```

Returns immediately. Test runs in background.

### Run Speed Test with Streaming Progress (Admin Only)

```
GET /api/wireguard/speedtest/run/stream
```

Returns Server-Sent Events (SSE) stream with progress updates.

**Response (SSE):**

```
data: {"phase": "server_selection", "progress": 0.05, "message": "Selecting download server..."}

data: {"phase": "testing", "progress": 0.5, "message": "Run 2/3: DL 245.3 / UL 48.2 Mbit/s"}

data: {"phase": "complete", "progress": 1.0, "message": "Complete: DL 248.5 / UL 47.8 Mbit/s"}

data: {"type": "result", "status": "ok", "download_mbit": 248.5, "upload_mbit": 47.8, "rtt_ms": 28.5, "jitter_ms": 12.3}
```

### Get History

```
GET /api/wireguard/speedtest/history
```

**Query Parameters:**

- `range` - Time range: `6h`, `24h`, `7d`, `30d`, `90d`, `180d`, `y1`
- `limit` - Max results (default: 500, max: 5000)

### Get Storage Stats

```
GET /api/wireguard/speedtest/storage
```

### Update Retention (Admin Only)

```
PATCH /api/wireguard/speedtest/storage/retention
```

**Request:**

```json
{
  "retention_days": 90
}
```

### Purge Data (Admin Only)

```
DELETE /api/wireguard/speedtest/storage
```

## Rate Limits

| Endpoint Type | Authenticated | Unauthenticated |
|---------------|---------------|-----------------|
| Read (GET) | 100/min | 10/min |
| Write (POST/PUT/DELETE) | 30/min | 5/min |

## Pagination

Paginated endpoints support:

- `limit` - Results per page (max 100)
- `offset` - Skip N results

**Response includes:**

```json
{
  "data": [...],
  "total": 150,
  "limit": 50,
  "offset": 0
}
```

## Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Missing/invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Unprocessable Entity - Validation failed |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

## SDKs & Libraries

Official SDKs (planned):

- Python: `wirebuddy-python`
- JavaScript: `wirebuddy-js`

Community contributions welcome!

## OpenAPI Specification

Download OpenAPI spec:

```
https://vpn.example.com/api/openapi.json
```

## Next Steps

- [Authentication Guide](authentication.md) - Generate tokens
- [API Overview](overview.md) - Getting started
- [Security](../security/best-practices.md) - API security best practices
