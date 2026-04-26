# Rate Limiting

WireBuddy applies route-level rate limits to reduce brute-force and abuse risk.

## Goals

- Protect login/MFA flows from brute-force attempts
- Protect API endpoints from abusive traffic bursts
- Preserve service stability under load

## Effective Limits

Limits vary by endpoint class and auth context. Representative classes:

| Route Class | Authenticated | Unauthenticated |
|---|---|---|
| Login/MFA flows | stricter | stricter |
| Read-heavy API | higher | lower |
| Write operations | moderate | low |
| Public status-style routes | dedicated caps | dedicated caps |

For exact behavior, validate against runtime configuration and route decorators.

## Lockout Behavior

Repeated failed authentication attempts trigger temporary lockouts. Retry-After
is provided on lockout responses where applicable.

## Response Semantics

### 429 Too Many Requests

Returned when a route limit is exceeded. Clients should:

1. Respect Retry-After if present
2. Back off exponentially for repeated failures
3. Avoid parallel retries from multiple workers

## Operational Guidance

- Keep reverse-proxy client IP forwarding correct
- Ensure trusted-proxy handling is configured properly
- Monitor repeated 401/429 patterns in logs
- Avoid hardcoding request bursts in automation

## Automation Example

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

retry = Retry(
    total=3,
    status_forcelist=[429, 500, 502, 503, 504],
    backoff_factor=2,
    respect_retry_after_header=True,
)

session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=retry))
```

## Related

- [Authentication](authentication.md)
- [Security Overview](overview.md)
