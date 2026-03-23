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
