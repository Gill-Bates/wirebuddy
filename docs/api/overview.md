# API Overview

WireBuddy provides a REST API for operational and automation workflows.

## Base URL

```text
https://vpn.example.com/api
```

## Authentication

WireBuddy API authentication uses the same session model as the web UI:

- Session cookie: auth_token cookie (browser/UI)
- Bearer header: Authorization: Bearer <auth_token> (automation/API clients)

For node synchronization endpoints under /api/nodes/* (sync daemon flows), a
separate node secret plus certificate fingerprint validation is used.

See [API Authentication](authentication.md) for details.

## Endpoint Families

| Family | Description |
|---|---|
| /api/login, /api/logout, /api/me* | User authentication and MFA/session flows |
| /api/users/* | User administration |
| /api/passkeys/* | Passkey registration/login and admin controls |
| /api/wireguard/* | Interfaces, peers, stats, speedtest, settings |
| /api/dns/* | DNS resolver management, logs, blocklists, rules |
| /api/backup/* | Backup settings, create/validate/restore/list |
| /api/acme/* | Certificate management and challenge handling |
| /api/nodes/* | Multi-node management and node sync endpoints |
| /api/network/* | Network statistics |
| /api/system/status | Runtime health/status |

See [API Endpoints](endpoints.md) for the runtime-generated route list.

## OpenAPI Documentation

```text
https://vpn.example.com/docs
```

OpenAPI JSON:

```text
https://vpn.example.com/openapi.json
```

## Example

```bash
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  https://vpn.example.com/api/wireguard/peers
```

## Rate Limiting

API requests are rate-limited. Exact limits depend on route class and auth
state. See [Rate Limiting](../security/rate-limiting.md).

## Next Steps

- [API Authentication](authentication.md)
- [API Endpoints](endpoints.md)
- [Security Best Practices](../security/best-practices.md)
