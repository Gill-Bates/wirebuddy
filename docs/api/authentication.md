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

Use the normal login endpoint and capture the resulting session token from your
client flow.

```text
POST /api/login
```

For MFA-enabled users, complete the MFA verification step:

```text
POST /api/mfa/verify
```

Then send requests with either cookie auth (browser-like clients) or Bearer
header auth.

## Node Sync Authentication

Node daemon synchronization routes under /api/nodes/* (for example enroll,
heartbeat, config/events sync, node speedtest submit/progress) use dedicated
node authentication:

- Authorization: Bearer <node_api_secret>
- X-Client-Cert-Fingerprint header

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

### 429 Too Many Requests

Rate-limited request. Respect Retry-After when provided.

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
