# API Overview

WireBuddy provides a RESTful API for programmatic access to all functionality.

## Base URL

```
https://vpn.example.com/api
```

## Authentication

All API requests require authentication via Bearer token.

See [API Authentication](authentication.md) for details.

## Endpoints

| Resource | Description |
|----------|-------------|
| `/api/auth/*` | Authentication and session management |
| `/api/wireguard/interfaces/*` | WireGuard interface management |
| `/api/wireguard/peers/*` | Peer management |
| `/api/dns/*` | DNS configuration and query logs |
| `/api/metrics/*` | Traffic statistics and analytics |
| `/api/users/*` | User management (admin only) |
| `/api/wireguard/settings/*` | WireGuard settings (admin only) |

See [API Endpoints](endpoints.md) for complete reference.

## Quick Example

```bash
# Get all peers
curl -H "Authorization: Bearer YOUR_TOKEN" \
  https://vpn.example.com/api/wireguard/peers
```

## OpenAPI Documentation

WireBuddy provides interactive API documentation via Swagger UI:

```
https://vpn.example.com/docs
```

!!! note
    Swagger UI can be disabled via `SWAGGER_ENABLED=false` environment variable.

## Rate Limiting

API requests are rate-limited:

- **Authenticated:** 100 requests/minute
- **Unauthenticated:** 10 requests/minute

See [Rate Limiting](../security/rate-limiting.md) for details.

## Next Steps

- [Authentication Guide](authentication.md) - Generate API tokens
- [Endpoint Reference](endpoints.md) - Complete API documentation
