# API Authentication

WireBuddy API requires authentication via Bearer tokens.

## Generating API Tokens

### Via Web UI

1. Login to WireBuddy
2. Navigate to **Profile → API Tokens**
3. Click **Create Token**
4. Configure:
   - **Name:** Descriptive label
   - **Expiration:** Never, 30 days, 90 days, 1 year
   - **Permissions:** Read-only or Full (admin only)
   - **IP Whitelist:** Optional IP restrictions
5. Click **Create**
6. **Copy token immediately** (shown only once)

### Token Format

```
wb_1234567890abcdefghijklmnopqrstuvwxyz
```

Tokens are prefixed with `wb_` for easy identification.

## Using Tokens

### HTTP Header

Include token in `Authorization` header:

```bash
curl -H "Authorization: Bearer wb_YOUR_TOKEN_HERE" \
  https://vpn.example.com/api/peers
```

### Query Parameter (Not Recommended)

Alternatively, pass as query parameter:

```bash
curl https://vpn.example.com/api/peers?token=wb_YOUR_TOKEN_HERE
```

!!! warning
    Query parameter authentication is less secure (logged in access logs). Use header-based authentication.

## Token Permissions

| Permission | Access Level |
|------------|--------------|
| **Read-only** | GET requests only (view data) |
| **Full** | All methods (create, update, delete) - Admin only |

## Token Lifecycle

### Expiration

Tokens expire based on configuration:

- **Never:** No expiration (use with caution)
- **30 days:** Recommended for automation
- **90 days:** Longer-lived scripts
- **1 year:** Maximum expiration

Expired tokens return `401 Unauthorized`.

### Revocation

Revoke tokens anytime:

1. **Profile → API Tokens**
2. Select token
3. Click **Revoke**

Revoked tokens immediately become invalid.

### Rotation

Best practice: Rotate tokens regularly

1. Create new token
2. Update scripts/automation
3. Revoke old token
4. Verify new token works

## Security Best Practices

### Storage

- ✅ Store in environment variables or secret manager
- ✅ Use file permissions (`chmod 600`) for token files
- ❌ Don't hardcode in source code
- ❌ Don't commit to version control

Example:

```bash
# .env
WIREBUDDY_API_TOKEN=wb_your_token_here

# Script
TOKEN=$(cat ~/.wirebuddy_token)
curl -H "Authorization: Bearer $TOKEN" ...
```

### Transmission

- ✅ Always use HTTPS
- ✅ Use header-based authentication
- ❌ Don't pass tokens in URLs
- ❌ Don't log tokens

### Scope

- Use read-only tokens when possible
- Create separate tokens for different purposes
- Use IP whitelisting for server-to-server

## Error Responses

### 401 Unauthorized

Missing or invalid token:

```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token"
}
```

**Solutions:**

- Verify token is correct
- Check token hasn't expired
- Ensure token hasn't been revoked

### 403 Forbidden

Insufficient permissions:

```json
{
  "error": "Forbidden",
  "message": "Insufficient permissions for this operation"
}
```

**Solutions:**

- Use token with full permissions
- Use admin account token
- Check endpoint requires admin access

### 429 Too Many Requests

Rate limit exceeded:

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 60 seconds"
}
```

**Solutions:**

- Reduce request frequency
- Implement exponential backoff
- Contact admin to increase limits

## Example: Python

```python
import requests

API_URL = "https://vpn.example.com/api"
TOKEN = "wb_your_token_here"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# Get all peers
response = requests.get(f"{API_URL}/peers", headers=headers)
peers = response.json()

for peer in peers:
    print(f"{peer['name']}: {peer['status']}")
```

## Example: Bash

```bash
#!/bin/bash

API_URL="https://vpn.example.com/api"
TOKEN="wb_your_token_here"

# Get all interfaces
curl -s -H "Authorization: Bearer $TOKEN" \
  "$API_URL/interfaces" | jq .
```

## Example: JavaScript

```javascript
const API_URL = 'https://vpn.example.com/api';
const TOKEN = 'wb_your_token_here';

async function getPeers() {
  const response = await fetch(`${API_URL}/peers`, {
    headers: {
      'Authorization': `Bearer ${TOKEN}`
    }
  });
  
  const peers = await response.json();
  console.log(peers);
}

getPeers();
```

## Next Steps

- [API Endpoints](endpoints.md) - Complete endpoint reference
- [Rate Limiting](../security/rate-limiting.md) - Rate limit details
- [Security Best Practices](../security/best-practices.md) - API security
