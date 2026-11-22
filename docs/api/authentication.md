# API Authentication

WireBuddy API access is based on application sessions.

## Authentication Modes

### 1) Browser Session Cookie

After login, the UI uses an auth_token cookie for authenticated API requests.

### 2) Bearer Header

Automation clients can use the same auth token in the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  https://vpn.example.com/api/wireguard/peers
```

Important:

- There is currently no separate long-lived API-token subsystem.
- Bearer auth validates the same session token model used by cookie auth.

## How to Obtain an Auth Token

Send the credentials as JSON to the login endpoint. On success, the response
returns the token in `data.token` (with `data.expires_at`) and also sets the
`auth_token` cookie.

```bash
curl -s -X POST https://vpn.example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username": "YOUR_USERNAME", "password": "YOUR_PASSWORD"}'
```

For users with TOTP enabled, the login response contains `mfa_required: true`
and an `mfa_token` instead of a session token. Complete the login with the
same `username`, that `mfa_token` and a TOTP or recovery `code`:

```text
POST /api/mfa/verify
```

Then send requests with either cookie auth (browser-like clients) or Bearer
header auth. Cookie sessions are extended on activity (up to 24 hours);
Bearer requests do not extend the session, so a token used only as a Bearer
header expires one hour after login.

When the built-in HTTPS listener is enabled or `WIREBUDDY_REQUIRE_HTTPS_AUTH`
is set, login over plain HTTP is rejected with `400`, except from loopback.

## Node Sync Authentication

Node daemon synchronization routes under /api/nodes/* (for example enroll,
heartbeat, config/events sync, node speedtest submit/progress) use dedicated
node authentication:

- `POST /api/nodes/enroll` is authenticated by a signed enrollment token
  and the node's self-signed certificate.
- All later sync requests require `Authorization: Bearer <node_api_secret>`.
- When the built-in HTTPS listener is enabled or `WIREBUDDY_REQUIRE_HTTPS_AUTH`
  is set, enrollment and all later sync requests over plain HTTP are rejected
  with `400`, except from loopback.
- The `X-Client-Cert-Fingerprint` header is only evaluated when it comes from a
  proxy listed in `WIREBUDDY_MTLS_PROXIES` (no proxy is trusted by default
  for this header, and `WIREBUDDY_TRUSTED_PROXIES` does not count). Then it must match the fingerprint stored at enrollment;
  otherwise it is ignored and the Bearer secret is the only credential.

This is separate from user session auth.

## Error Semantics

### 401 Unauthorized

Typical causes:

- Missing auth token
- Invalid token
- Expired session

### 403 Forbidden

Typical causes:

- Authenticated but missing admin privileges
- Account disabled

### 428 Precondition Required

The account must change its password first (for example after an admin reset).
Only the password change and logout endpoints stay reachable.

### 429 Too Many Requests

Rate-limited request or login lockout. Respect Retry-After when provided.
`POST /api/wireguard/speedtest/run` also returns `429` during the 30-second
cooldown after a successful speed test, and `409` while a test is running.

## Security Recommendations

- Use HTTPS only.
- Prefer Authorization headers for non-browser automation.
- Do not log tokens.
- Rotate/re-authenticate automation sessions regularly.

## Examples

### Bash

```bash
API_URL="https://vpn.example.com/api"
TOKEN="YOUR_AUTH_TOKEN"

curl -s -H "Authorization: Bearer $TOKEN" \
  "$API_URL/wireguard/interfaces"
```

### Python

```python
import requests

api_url = "https://vpn.example.com/api"
token = "YOUR_AUTH_TOKEN"
headers = {"Authorization": f"Bearer {token}"}

resp = requests.get(f"{api_url}/wireguard/peers", headers=headers, timeout=10)
print(resp.status_code)
print(resp.json())
```

## Next Steps

- [API Endpoints](endpoints.md)
- [Rate Limiting](../security/rate-limiting.md)
- [Security Best Practices](../security/best-practices.md)
