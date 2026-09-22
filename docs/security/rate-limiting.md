# Rate Limiting

WireBuddy applies route-level rate limits to reduce brute-force and abuse risk.

## Goals

- Protect login/MFA flows from brute-force attempts
- Protect API endpoints from abusive traffic bursts
- Preserve service stability under load

## Effective Limits

Each route is decorated with one of these classes, defined in
`app/utils/rate_limit.py`:

| Class | Limit | Applied to |
|---|---:|---|
| Authentication | `5/minute` | Login and MFA verification |
| Critical | `3/minute` | Secret-bearing and high-impact operations: peer config/QR download, backup restore, node create/delete/token, WireGuard settings changes |
| Heavy | `10/minute` | Expensive operations: peer creation, DNS start/stop/restart, DNS config and blocklist changes |
| General API | `120/minute` | Ordinary authenticated API reads and writes |
| Default | `60/minute` | Everything else, including the public `/status` page |

`WIREBUDDY_RATE_LIMIT_UI_HEAVY` (default `60/minute`) overrides the limit for
expensive UI routes. The other classes are application constants.

Limits are keyed on the client IP, so correct trusted-proxy configuration is a
prerequisite — see [Operational Guidance](#operational-guidance).

## Lockout Behavior

Repeated failed authentication attempts trigger temporary lockouts. Retry-After
is provided on lockout responses where applicable.

### Per-IP lockout

Each client IP accumulates a progressive delay after failed login attempts.
Delay increases with each failure; subsequent attempts from the same IP during
the lockout window return 429.

### Username-wide throttle

In addition to IP-based lockout, WireBuddy tracks failed attempts per username
across all source IPs. Once the threshold is reached, even a previously-unseen
IP is throttled for that account — slowing distributed password guessing across
rotating addresses.

The throttle is intentionally **short-capped** (maximum ~5 minutes) to avoid
creating a DoS-able permanent account lockout. A **fully completed** login from
any IP immediately clears the throttle for that username.

!!! important "MFA accounts"
    For accounts with MFA enabled, the counter is cleared only after the second
    factor has been verified — not after the password step. A correct password
    alone does not reset it. Otherwise an attacker who already knew the password
    could reset the counter between OTP guesses and defeat the throttle
    entirely.

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
