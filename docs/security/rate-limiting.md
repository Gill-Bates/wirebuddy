# Rate Limiting

WireBuddy implements progressive rate limiting to prevent abuse and brute-force attacks.

## Overview

Rate limiting protects against:

- 🔒 Brute-force password attacks
- 🚫 API abuse
- 💥 Denial of Service (DoS)
- 🤖 Automated scraping

## Rate Limit Tiers

| Endpoint | Authenticated | Unauthenticated |
|----------|---------------|-----------------|
| **Login** | 5/15min | 5/15min |
| **MFA Verify** | 5/5min | 5/5min |
| **Password Reset** | 3/hour | 3/hour |
| **API GET** | 100/min | 10/min |
| **API POST/PUT/DELETE** | 30/min | 5/min |
| **Status Page** | 60/min | 60/min |

## Progressive Lockout

Failed attempts trigger exponential backoff:

| Violation | Lockout Duration |
|-----------|------------------|
| 1st | 1 minute |
| 2nd | 5 minutes |
| 3rd | 15 minutes |
| 4th+ | 1 hour |

Lockout duration resets after 24 hours of no violations.

## Rate Limit Headers

API responses include rate limit information:

```http
HTTP/1.1 200 OK
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1679143200
Retry-After: 60
```

- **X-RateLimit-Limit:** Maximum requests in window
- **X-RateLimit-Remaining:** Requests remaining
- **X-RateLimit-Reset:** Timestamp when limit resets (Unix epoch)
- **Retry-After:** Seconds until retry (when rate limited)

## Rate Limit Responses

### 429 Too Many Requests

When rate limit is exceeded:

```json
{
  "error": "Too Many Requests",
  "message": "Rate limit exceeded. Try again in 60 seconds",
  "retry_after": 60,
  "limit": 100,
  "window": 60
}
```

## Configuration

### Global Settings

**Settings → Security → Rate Limiting**

- **Enable Rate Limiting:** Master toggle
- **Strict Mode:** More aggressive limits

### Per-Endpoint Limits

**Settings → Security → Rate Limiting → Endpoints**

Customize limits per endpoint:

```json
{
  "login": {
    "attempts": 5,
    "window": 900,
    "lockout": 60
  },
  "api_read": {
    "authenticated": 100,
    "unauthenticated": 10,
    "window": 60
  }
}
```

### IP Whitelist

Exempt trusted IPs from rate limiting:

**Settings → Security → Rate Limiting → Whitelist**

```
# Internal monitoring
192.168.1.100/32

# Office network
203.0.113.0/24
```

!!! warning
    Use sparingly. Whitelisted IPs can abuse the system.

## Implementation Details

### Storage Backend

WireBuddy uses in-memory storage for rate limits:

- **Fast:** No database queries
- **Scalable:** Handles high request volume
- **Automatic cleanup:** Expired entries removed

### Key Generation

Rate limits are tracked per:

```python
# IP-based (unauthenticated)
key = f"ratelimit:{endpoint}:{client_ip}"

# User-based (authenticated)
key = f"ratelimit:{endpoint}:user:{user_id}"
```

### Sliding Window

WireBuddy uses sliding window algorithm:

```python
def check_rate_limit(key: str, limit: int, window: int) -> bool:
    now = time.time()
    window_start = now - window
    
    # Get requests in window
    requests = [ts for ts in get_requests(key) if ts > window_start]
    
    # Check limit
    if len(requests) >= limit:
        return False  # Rate limited
    
    # Record request
    add_request(key, now)
    return True  # Allowed
```

## Monitoring

### View Rate Limits

**Dashboard → Security → Rate Limits**

- Current limits for each endpoint
- Active lockouts
- Top offending IPs

### Audit Logs

Rate limit violations are logged:

```json
{
  "timestamp": "2026-03-15T14:30:00Z",
  "event": "rate_limit_exceeded",
  "endpoint": "/api/peers",
  "ip": "203.0.113.42",
  "user": "admin",
  "limit": 100,
  "window": 60,
  "lockout_duration": 60
}
```

### Alerts

(Future feature)

Configure alerts for:

- Multiple rate limit violations from same IP
- Distributed attack patterns
- Unusual traffic spikes

## Bypassing Rate Limits

### For Legitimate Use

If you're getting rate limited legitimately:

1. **Increase limits:** Settings → Security → Rate Limiting
2. **Use authentication:** Authenticated requests have higher limits
3. **Whitelist IP:** Add your IP to whitelist
4. **Implement backoff:** Exponential backoff in scripts

### For Automation

Best practices for scripts/automation:

```python
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Retry strategy
retry_strategy = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=2,  # 1s, 2s, 4s
    respect_retry_after_header=True
)

adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)

# Use session for requests
response = session.get(
    "https://vpn.example.com/api/peers",
    headers={"Authorization": f"Bearer {TOKEN}"}
)

# Check rate limit headers
remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
if remaining < 10:
    reset = int(response.headers.get('X-RateLimit-Reset', 0))
    wait_time = max(0, reset - time.time())
    print(f"Approaching limit, waiting {wait_time}s")
    time.sleep(wait_time)
```

## Integration with fail2ban

Automatically ban IPs with repeated violations:

```ini
# /etc/fail2ban/filter.d/wirebuddy.conf
[Definition]
failregex = ^.*rate_limit_exceeded.*ip=<HOST>$
ignoreregex =

# /etc/fail2ban/jail.d/wirebuddy.conf
[wirebuddy-ratelimit]
enabled = true
port = http,https
filter = wirebuddy
logpath = /var/log/wirebuddy/audit.log
maxretry = 10
findtime = 600
bantime = 3600
```

## Security Considerations

### Distributed Attacks

Rate limiting by IP may not stop:

- **Distributed attacks:** Multiple IPs
- **Botnets:** Large IP pools

Additional protection:

- Cloudflare or similar WAF
- CrowdSec for collaborative defense
- CAPTCHA for suspicious patterns (future feature)

### IP Spoofing

Behind reverse proxy, ensure:

- Only trusted proxies can set `X-Forwarded-For`
- Use **Trusted Proxies** configuration
- Validate `X-Forwarded-For` format

## Troubleshooting

### Legitimate Users Getting Blocked

**Problem:** Users reporting "rate limit exceeded"

**Solutions:**

1. Review rate limit configuration (too strict?)
2. Check for misconfigured scripts/automation
3. Temporarily increase limits
4. Whitelist specific IPs if justified

### Rate Limits Not Working

**Problem:** Attackers bypassing rate limits

**Causes:**

1. Rate limiting disabled
2. IP extracted incorrectly (proxy misconfiguration)
3. Attacker using multiple IPs

**Solutions:**

1. Verify rate limiting is enabled
2. Check **Trusted Proxies** configuration
3. Implement additional layers (WAF, CrowdSec)

### False Positives

**Problem:** Internal services getting rate limited

**Solutions:**

1. Whitelist internal IP ranges
2. Use API tokens (higher limits)
3. Implement proper retry logic with backoff

## Best Practices

### For Admins

- ✅ Keep rate limiting enabled
- ✅ Monitor audit logs for violations
- ✅ Whitelist only when necessary
- ✅ Set reasonable limits (not too strict)
- ✅ Configure reverse proxy correctly
- ✅ Use fail2ban for repeat offenders

### For Developers

- ✅ Implement exponential backoff
- ✅ Respect `Retry-After` header
- ✅ Cache responses when possible
- ✅ Use authenticated requests
- ✅ Monitor `X-RateLimit-Remaining`
- ❌ Don't retry immediately on 429

## Next Steps

- [Authentication](authentication.md) - Login security
- [Security Overview](overview.md) - Complete security docs
- [Best Practices](best-practices.md) - Security hardening
- [API Authentication](../api/authentication.md) - API tokens
