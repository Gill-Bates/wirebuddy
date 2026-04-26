# Security Configuration

Advanced security settings in WireBuddy.

## Password Policy

Configure password requirements:

**Settings → Security → Password Policy**

- **Minimum Length:** 8-32 characters
- **Complexity:** Require uppercase, lowercase, numbers, special characters
- **Password History:** Prevent reuse of last N passwords
- **Expiration:** Force password changes every N days (optional)

## Session Configuration

**Settings → Security → Sessions**

### Session Timeout

- **15 minutes:** High security environments
- **30 minutes:** Default, balanced security
- **1 hour:** Convenience
- **4 hours:** Maximum allowed

### Session Renewal

- **On Activity:** Extend session on each request
- **Manual:** Require explicit renewal

### Concurrent Sessions

- **Allow:** Users can have multiple active sessions
- **Deny:** Only one session per user

## HTTPS Configuration

### Force HTTPS

**Settings → Security → HTTPS**

Enable "Force HTTPS" to redirect all HTTP requests to HTTPS.

Required for:

- HSTS
- Secure cookies
- WebAuthn (passkeys)

### SSL/TLS Settings

**Reverse Proxy (Recommended):**

Configure TLS in your reverse proxy (Caddy, nginx):

```nginx
# nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
```

**Built-in ACME:**

See [Let's Encrypt Configuration](../features/acme.md).

### HSTS

HTTP Strict Transport Security header:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Enabled automatically when "Force HTTPS" is on.

## CSRF Protection

**Settings → Security → CSRF**

- **Enabled:** Double-submit cookie pattern (recommended)
- **SameSite:** Lax (default), Strict, or None
- **Origin Validation:** Verify Origin/Referer headers

## Rate Limiting

**Settings → Security → Rate Limiting**

### Login Rate Limiting

- **Attempts:** Maximum failed login attempts (default: 5)
- **Window:** Time window in minutes (default: 15)
- **Lockout Duration:** Initial lockout (default: 1 minute)
- **Exponential Backoff:** Increase lockout on repeated violations

### API Rate Limiting

- **Authenticated:** Requests per minute (default: 100)
- **Unauthenticated:** Requests per minute (default: 10)

See [Rate Limiting Guide](../security/rate-limiting.md) for details.

## IP Whitelisting

**Settings → Security → IP Whitelist**

Restrict access to specific IP ranges:

```
# Allow office network
Allow: 203.0.113.0/24

# Allow VPN clients
Allow: 10.8.0.0/24

# Block all others (implicit)
```

!!! warning
    Ensure you don't lock yourself out. Always test from allowed IP first.

## Passkey Configuration

Passkeys are managed per user (via user management UI and passkey API), not via a global passkey policy screen in Settings.

Current behavior:

- Users can register/login with WebAuthn passkeys.
- Admins can enable onboarding, disable passkeys, and reset all passkeys per user.
- RP identity is controlled via environment (`PASSKEY_RP_ID`, `PASSKEY_RP_NAME`).

See [Passkeys Guide](../security/passkeys.md).

## MFA Configuration

**Settings → Security → Multi-Factor Authentication**

- **Enforce MFA:** Require MFA for all admin accounts
- **Grace Period:** Days before MFA is required (default: 7)
- **Recovery Codes:** Number of backup codes (default: 10)

## Audit Logging

**Settings → Security → Audit Log**

Log security-sensitive events:

- ✅ Authentication (login/logout)
- ✅ Failed login attempts
- ✅ Password changes
- ✅ MFA enrollment/use
- ✅ User creation/deletion
- ✅ Settings changes
- ✅ Peer/interface modifications

### Log Retention

- **30 days:** Minimum recommended
- **90 days:** Compliance requirement (varies)
- **1 year:** Long-term auditing

### Export Logs

Export audit logs for external analysis:

**Settings → Security → Audit Log → Export**

Formats: CSV, JSON, Syslog

## Security Headers

WireBuddy automatically sets security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Content-Security-Policy: default-src 'self'; ...
```

### Custom CSP

**Settings → Security → Content Security Policy**

Add custom CSP directives for third-party integrations.

## Trusted Proxies

WireBuddy trusts proxy headers only from explicitly trusted proxy sources.

For the public status page (`/status`), trusted proxy CIDRs are configured with:

```bash
WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS=127.0.0.1/32,192.168.1.10/32
```

Notes:

- Loopback hops are always trusted for `/status`
- Private IP ranges are **not** auto-trusted for `/status`
- If a reverse proxy is on a LAN address, add that CIDR explicitly

## Secrets Encryption

WireBuddy encrypts sensitive data at rest:

- **Algorithm:** Fernet (AES-128-CBC + HMAC-SHA256)
- **Key Derivation:** PBKDF2 with `WIREBUDDY_SECRET_KEY`
- **Per-Row Salt:** Unique salt per encrypted field

Encrypted fields:

- WireGuard private keys
- TOTP secrets
- ACME account keys
- API tokens (SHA-256 hash, not encrypted)

!!! danger "Secret Key Security"
    Never change `WIREBUDDY_SECRET_KEY` after deployment. All encrypted data will become unrecoverable.

## Database Security

### SQLite Security

- **Location:** `data/wirebuddy.db` (inside Docker volume)
- **Permissions:** 600 (owner read/write only)
- **Encryption:** Not encrypted by default (use dm-crypt for volume encryption)

### Backup Encryption

Encrypt backups:

```bash
# Backup with GPG encryption
tar cz data/ | gpg -e -r your-key@example.com > backup.tar.gz.gpg

# Restore
gpg -d backup.tar.gz.gpg | tar xz
```

## Container Security

### Hardening

```yaml
# docker-compose.yml
services:
  wirebuddy:
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /run
```

### User Namespace

Run container as non-root:

```yaml
user: "1000:1000"
```

## Firewall Integration

### fail2ban

Automatically ban IPs with failed login attempts:

```ini
# /etc/fail2ban/filter.d/wirebuddy.conf
[Definition]
failregex = ^.*Failed login attempt for user .* from <HOST>$
ignoreregex =

# /etc/fail2ban/jail.d/wirebuddy.conf
[wirebuddy]
enabled = true
port = http,https
filter = wirebuddy
logpath = /var/log/wirebuddy/auth.log
maxretry = 5
bantime = 3600
```

### CrowdSec

Integrate with CrowdSec for collaborative security:

```bash
# Install CrowdSec bouncer
docker run -d --name crowdsec-bouncer \
  -e CROWDSEC_AGENT_HOST=crowdsec:8080 \
  crowdsecurity/nginx-crowdsec-bouncer
```

## Compliance

### GDPR

- **Data Minimization:** Only collect necessary data
- **Right to Deletion:** Users can request account deletion
- **Export:** Users can export their data
- **Consent:** Explicit consent for data processing

### SOC 2

- **Access Control:** Role-based permissions
- **Audit Logging:** Comprehensive event logging
- **Encryption:** Data encrypted at rest and in transit
- **Monitoring:** Real-time security event monitoring

## Security Scanning

### Vulnerability Scanning

Scan Docker image:

```bash
# Trivy
trivy image giiibates/wirebuddy:latest

# Grype
grype giiibates/wirebuddy:latest
```

### Dependency Scanning

Check Python dependencies:

```bash
# Safety
safety check -r requirements.txt

# Bandit (static analysis)
bandit -r app/
```

## Next Steps

- [Security Overview](../security/overview.md)
- [Best Practices](../security/best-practices.md)
- [Rate Limiting](../security/rate-limiting.md)
- [Passkeys](../security/passkeys.md)
