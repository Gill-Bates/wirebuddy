---
title: Security Overview
---

# Security Overview

WireBuddy combines authenticated web sessions, role checks, CSRF and origin
validation, request throttling, encrypted application secrets, and a restricted
container capability set. Deployment configuration remains part of the security
boundary, especially the secret key, reverse proxy, host firewall, and data
directory.

## Authentication and authorization

WireBuddy supports password login, password plus TOTP, and WebAuthn passkeys.
Accounts have one of two roles:

| Role | Access |
|---|---|
| `admin` | May change interfaces, peers, users, DNS, certificates, backups, and settings |
| `user` | Read-only access to permitted UI and API views |

Passwords are stored with PBKDF2-SHA256 using 600,000 iterations and a random
salt. New passwords must be at least eight characters and at most 72 UTF-8
bytes, must not be in the built-in common-password list, and must satisfy at
least three of the uppercase, lowercase, digit, and special-character groups.

TOTP uses six-digit, 30-second codes and produces eight one-time recovery codes
during enrollment. Passkeys store public credential material; private keys stay
with the authenticator. See [Authentication](authentication.md) and
[Passkeys](passkeys.md).

## Sessions and browser protection

Successful login creates a random token. Only its SHA-256 hash is stored in
SQLite; the browser receives the token in an `HttpOnly`, `SameSite=Lax` cookie.
Cookie-authenticated activity refreshes the one-hour idle expiry up to a fixed
24-hour maximum. Bearer-token API use does not refresh the expiry. Logout deletes
the current token, while password changes, resets, and account disablement revoke
all sessions for that user.

State-changing cookie-authenticated requests require CSRF validation. WireBuddy
uses a double-submit token and validates browser origins. Configure
`WIREBUDDY_PUBLIC_ORIGIN` and any additional
`WIREBUDDY_CSRF_ALLOWED_ORIGINS` when a reverse proxy changes the public origin.

Responses receive a Content Security Policy, `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, and a strict referrer policy. HSTS is emitted
for HTTPS requests or when explicitly forced. Cookie `Secure` handling depends
on trustworthy HTTPS detection; do not trust forwarded headers from arbitrary
clients.

## Secrets at rest

`WIREBUDDY_SECRET_KEY` is required in master mode and must contain at least 32
UTF-8 bytes. WireBuddy uses it as the vault pepper for WireGuard private keys,
preshared keys, TOTP secrets, and sensitive stored settings.

Current vault writes use Fernet authenticated encryption. A PBKDF2-SHA256 master
derivation (480,000 iterations by default) and per-row HKDF-SHA256 context
produce distinct row keys. Stored session tokens and TOTP recovery codes are
one-way hashed instead of encrypted.

ACME account and certificate private keys are files under
`/app/data/certs/` with mode `0600`; they are not wrapped by the application
vault. Protect and back up the whole data volume accordingly.

!!! danger
    Losing or changing `WIREBUDDY_SECRET_KEY` makes existing vault-encrypted
    values unreadable. Keep it outside the repository and retain a secure backup.

## Proxy and host trust

Proxy trust has two layers:

- `FORWARDED_ALLOW_IPS` controls which peers Uvicorn trusts for
  `X-Forwarded-*` processing.
- `TRUSTED_PROXY_CIDRS` controls application-level client IP and HTTPS
  detection.

Defaults trust loopback only. Configure the exact proxy address or CIDR and
never use a wildcard. Incorrect trust can let clients spoof addresses used by
rate limiting, audit logs, secure-cookie decisions, or status-page access.

`WIREBUDDY_ALLOWED_HOSTS` can add Host-header validation. The public status page
has a separate trusted-proxy setting and is intended only for WireGuard-internal
clients.

## Rate limiting and lockout

Route decorators apply request limits such as 5/minute for authentication,
10/minute for expensive operations, 120/minute for general API operations, and
3/minute for critical operations. The application also records failed logins
against source IP, username-plus-IP, and username-wide keys. Exponential
lockouts begin after configurable thresholds and return `429` with
`Retry-After`.

See [Rate Limiting](rate-limiting.md) and
[Environment Variables](../configuration/environment.md#login-lockout-tuning)
for the current defaults.

## Container and network boundary

The supplied Compose service:

```yaml
network_mode: host
cap_drop:
  - ALL
cap_add:
  - NET_ADMIN
security_opt:
  - no-new-privileges:true
devices:
  - /dev/net/tun:/dev/net/tun
```

The process runs as root inside the container because WireGuard and iptables
management require network administration. It does not run as an unprivileged
UID and the supplied root filesystem is not read-only. Host networking also
means services bind directly on the host; protect the GUI, DNS, and WireGuard
ports with the host and upstream firewalls.

## Operational controls

- The temporary bootstrap admin password is logged once and must be changed at
  first login.
- Swagger is disabled unless enabled under **Settings → General** and remains
  admin-authenticated.
- Login, MFA, passkey, password, user, peer, interface, and settings actions
  write security-relevant application logs.
- Backups omit active sessions and login-attempt state. Their integrity key is
  derived from `WIREBUDDY_SECRET_KEY`; transport/storage encryption is the
  operator's responsibility.
- The built-in ACME client stores certificates but does not automatically renew
  them or configure a TLS listener.

## Current product boundaries

The current release does not include an active-session manager, login-history
UI, separate API-token subsystem, Security settings tab, automatic certificate
renewal, SIEM export, or built-in vulnerability/compliance certification.

For a deployment checklist, continue with
[Security Best Practices](best-practices.md) and
[Security Configuration](../configuration/security.md).
