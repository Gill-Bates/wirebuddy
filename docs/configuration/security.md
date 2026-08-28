# Security Configuration

WireBuddy applies its core security controls by default. There is no separate
**Settings → Security** tab in the current UI. Account security is managed from
**Users**, while deployment controls are configured through environment
variables and the reverse proxy.

## Passwords

Passwords are hashed with PBKDF2-HMAC-SHA256 using 600,000 iterations and a
random per-password salt.

The enforced password policy is:

- minimum 8 characters
- maximum 72 UTF-8 bytes
- no control characters or known common passwords
- at least three of uppercase, lowercase, number, and special character

The bootstrap administrator receives a random temporary password in the first
startup log and must replace it at first login. Administrator password resets
also force a change at next login and revoke existing sessions.

Password policy parameters are not configurable in the current UI.

## Sessions and Cookies

Authentication uses opaque random session tokens. Only SHA-256 token hashes are
stored in SQLite.

- Idle validity starts at 1 hour.
- Cookie-authenticated activity extends the idle expiry.
- Absolute session lifetime is 24 hours.
- The authentication cookie is `HttpOnly` and `SameSite=Lax`.
- The `Secure` flag is enabled when HTTPS is detected or
  `FORCE_HTTPS_COOKIES` is set. With the built-in HTTPS listener it is always
  set, because the request scheme is `https` directly.

There is currently no session-duration setting or active-session management
screen.

## Built-in HTTPS Listener

WireBuddy can terminate TLS itself instead of relying on a reverse proxy.
Enable **Settings → General → Serve GUI over HTTPS**. The setting is read at
startup, so restart WireBuddy afterwards.

This is a single, all-or-nothing switch (`gui_https_enabled`, also settable via
`PATCH /api/wireguard/settings`). Enabling it does two things: the GUI port
serves TLS, and logins and node enrollments reject plain-HTTP transports, so
session cookies and node secrets are never sent in clear text. There is no
separate policy toggle. The ACME challenge path is never affected.

Which certificate is presented is decided automatically:

1. A **Let's Encrypt** certificate for the configured Server FQDN, if one exists
   under `data/certs/<fqdn>/` and has not expired. Staging certificates are
   ignored.
2. Otherwise a **self-signed** certificate, generated on demand into
   `data/certs/_selfsigned/`. Browsers show a trust warning for it.

Request a certificate in **Settings → Let's Encrypt** and restart; the ACME
certificate then replaces the self-signed one automatically. Nothing needs to be
copied by hand, and the two never share files. The Settings page shows which
certificate would be served.

### Let's Encrypt while HTTPS is enabled

ACME HTTP-01 validation always connects to **port 80 over plain HTTP**. Once the
GUI port speaks TLS, WireBuddy therefore also starts a small plaintext listener
that answers only `/.well-known/acme-challenge/…` and redirects everything else
to HTTPS. Certificate issue and renewal keep working, and no authenticated
surface is exposed in clear text.

That listener defaults to port 80 and is configured with the `gui_acme_http_port`
setting; set it to `0` to disable it. Make sure the port is reachable from the
internet, otherwise validation fails.

Certificates are read at startup only. **Restart WireBuddy after issuing or
renewing a certificate** for the new one to be served.

## HTTPS and Reverse Proxies

If you prefer to terminate TLS upstream instead of using the built-in listener,
leave **Serve GUI over HTTPS** off and terminate in Caddy, nginx, Traefik, or
another trusted reverse proxy. Do not enable both — WireBuddy would then expect
a TLS connection on a port the proxy speaks plain HTTP to.

For a same-host proxy, the Docker defaults trust loopback. For other proxy
addresses, configure both:

```bash
WIREBUDDY_TRUST_PROXY_HEADERS=1
FORWARDED_ALLOW_IPS=192.168.1.10
TRUSTED_PROXY_CIDRS=192.168.1.10/32
WIREBUDDY_PUBLIC_ORIGIN=https://vpn.example.com
```

`FORWARDED_ALLOW_IPS` controls which peers Uvicorn trusts for
`X-Forwarded-*`; `TRUSTED_PROXY_CIDRS` controls application-level client-IP and
HTTPS detection. Do not use broad CIDRs unless the complete range is controlled
by your proxy infrastructure.

HSTS is emitted for requests detected as HTTPS. Set
`WIREBUDDY_FORCE_HSTS=1` only when TLS terminates upstream and scheme detection
cannot be made reliable.

See [Environment Variables](environment.md#reverse-proxy-and-origin-handling)
and [Installation](../getting-started/installation.md#reverse-proxy).

## Host Validation

Enable Starlette's Trusted Host middleware with an explicit allowlist:

```bash
WIREBUDDY_ALLOWED_HOSTS=vpn.example.com,localhost
```

Leave this unset only when Host-header validation is handled by a trusted
front-end proxy.

## CSRF Protection

Browser mutations use a double-submit CSRF cookie plus Origin/Referer
validation. Cookie-authenticated API requests are protected; header-only Bearer
requests do not rely on cookies and are exempt from CSRF token matching.

For a reverse-proxy deployment, set the canonical origin:

```bash
WIREBUDDY_PUBLIC_ORIGIN=https://vpn.example.com
```

Additional legitimate origins can be listed in
`WIREBUDDY_CSRF_ALLOWED_ORIGINS`. CSRF protection cannot be disabled through
the UI.

## Security Headers

WireBuddy sends these headers by default:

```http
Content-Security-Policy: default-src 'self'; ...
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

The CSP permits the explicitly used map tiles, jsDelivr-hosted country flags,
and local application assets. There is no custom-CSP editor in the UI.

## Rate Limiting and Login Lockouts

SlowAPI route limits protect login, sensitive writes, expensive operations,
and general API traffic. Exceeded route limits return HTTP `429` with
`Retry-After`.

Failed logins are additionally tracked across:

- source IP
- username plus source IP
- username across changing source IPs

The progressive delays and thresholds can be tuned through the
`WIREBUDDY_LOGIN_*` variables documented under
[Login Lockout Tuning](environment.md#login-lockout-tuning). There is no
rate-limit toggle in the UI.

See [Rate Limiting](../security/rate-limiting.md).

## TOTP and Passkeys

TOTP and passkeys are managed per account from the administrator-only
**Users** page.

- TOTP enrollment requires confirmation before activation.
- Eight one-time recovery codes are delivered through a short-lived download.
- Disabling TOTP requires reauthentication.
- Passkeys support usernameless login and multiple credentials per account.
- Administrators can initiate onboarding and reset another user's passkeys.

There is no global MFA-enforcement or passkey-policy screen. See
[User Management](../features/users.md) and [Passkeys](../security/passkeys.md).

## Swagger

Swagger is disabled by default. Administrators can enable it under
**Settings → General → API Documentation**.

- UI: `/swagger`
- Schema: `/swagger/openapi.json`
- Access: authenticated administrators only

`SWAGGER_ENABLED` is not an environment variable in the current application.

## Public Status Page

The status page is disabled by default and can be enabled under
**Settings → General → Public Status Page**. It is intended for WireGuard
clients; authenticated administrators have an override.

When a reverse proxy fronts `/status`, list non-loopback proxy CIDRs in
`WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS`. See
[Status Page](status-page.md).

## Secrets at Rest

Sensitive values are wrapped with Fernet authenticated encryption. New values
use the vault v2 derivation scheme:

1. PBKDF2-HMAC-SHA256 derives a deployment master key from
   `WIREBUDDY_SECRET_KEY`.
2. HKDF-SHA256 plus a random per-row salt derives the row key.
3. Fernet encrypts and authenticates the value.

The default vault PBKDF2 work factor is 480,000. Do not change
`WIREBUDDY_SECRET_KEY`, `WIREBUDDY_PBKDF2_ITERATIONS`, or
`WIREBUDDY_DEPLOYMENT_ID` after encrypted data exists unless performing a
supported migration.

Encrypted data includes WireGuard private keys, preshared keys, OTP secrets,
and ACME account material. Session and recovery tokens are stored as hashes.
The SQLite file itself is not whole-database encrypted; use encrypted storage
when that threat model requires it.

## Container Hardening

The supplied Compose service:

- drops all capabilities and adds back only the six that are required:
  `NET_ADMIN` for WireGuard and iptables, and `NET_BIND_SERVICE`, `SETUID`,
  `SETGID`, `CHOWN`, `DAC_OVERRIDE` for the bundled Unbound resolver
- enables `no-new-privileges`
- mounts `/dev/net/tun`
- uses host networking as required by WireGuard
- limits JSON log-file growth

The container runs as root because WireGuard, iptables, Unbound, and network
namespace operations require privileges. Running the current image as an
arbitrary non-root UID or with a read-only root filesystem is not a supported
drop-in configuration.

## Operational Logging

WireBuddy emits structured security-relevant log events for authentication,
password changes, OTP/passkey changes, and administrative mutations. There is
no built-in audit-log browser or CSV/syslog export page. Forward container logs
to your logging system when centralized retention or alerting is required.

## Not Currently Implemented

The current release does not provide:

- a Security settings tab
- configurable password history or expiry
- a built-in application IP whitelist
- active-session browsing or individual remote-session revocation
- global MFA enforcement
- custom CSP editing
- a dedicated API-token subsystem
- built-in CrowdSec/fail2ban integration

Implement these controls at the reverse proxy, firewall, identity, or logging
layer where needed.

## Related

- [Security Overview](../security/overview.md)
- [Security Best Practices](../security/best-practices.md)
- [Environment Variables](environment.md)
- [API Authentication](../api/authentication.md)
