# Security Best Practices

This checklist complements WireBuddy's built-in controls. It reflects the
current UI and deployment model; controls not exposed by WireBuddy should be
implemented at the host or reverse-proxy layer.

## Protect the Secret Key

Generate a unique high-entropy `WIREBUDDY_SECRET_KEY` for every deployment:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

- Keep the value out of Git, images, screenshots, and logs.
- Store a protected recovery copy alongside your data backup procedure.
- Reuse the same key when recreating or upgrading the container.
- Do not change the key after encrypted WireGuard, OTP, or ACME values exist.

Protect the environment file:

```bash
chmod 600 .env
```

## Replace the Bootstrap Password

On first startup, retrieve the generated temporary password from the log:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy
```

Sign in as `admin` and complete the mandatory password change immediately. The
temporary password is invalidated after replacement.

WireBuddy requires at least three character categories, rejects common
passwords, and hashes passwords with PBKDF2-HMAC-SHA256. Prefer a password
manager-generated value.

## Enable Strong Account Authentication

Open the top-level **Users** page and configure each administrator account:

- register at least one passkey, ideally a second recovery authenticator
- or enable TOTP and securely store the recovery-code ZIP
- use a separate named account for every administrator
- keep the number of administrators small
- disable or remove accounts as soon as access is no longer needed

WireBuddy does not currently provide global MFA enforcement, active-session
management, or a dedicated login-history page. Enforce organizational policy
outside the application and monitor the structured authentication logs.

## Use HTTPS

Expose production installations through HTTPS. A same-host reverse proxy can
connect to WireBuddy on loopback; if the proxy is remote or containerized,
configure exact trust boundaries:

```bash
WIREBUDDY_TRUST_PROXY_HEADERS=1
FORWARDED_ALLOW_IPS=192.168.1.10
TRUSTED_PROXY_CIDRS=192.168.1.10/32
WIREBUDDY_PUBLIC_ORIGIN=https://vpn.example.com
WIREBUDDY_ALLOWED_HOSTS=vpn.example.com
```

- `FORWARDED_ALLOW_IPS` controls Uvicorn's forwarded-header trust.
- `TRUSTED_PROXY_CIDRS` controls application client-IP and HTTPS detection.
- `WIREBUDDY_PUBLIC_ORIGIN` makes CSRF and WebAuthn origin handling explicit.
- `WIREBUDDY_ALLOWED_HOSTS` rejects unexpected Host headers.

Never use `FORWARDED_ALLOW_IPS=*`. See
[Environment Variables](../configuration/environment.md#reverse-proxy-and-origin-handling).

## Restrict Network Exposure

Only expose the services you use:

- GUI/reverse proxy: TCP 8000 or your configured port
- WireGuard: configured UDP interface ports, commonly 51820
- DNS: TCP/UDP 53 only when VPN clients need the integrated resolver

Prefer firewall rules scoped to trusted management networks for the GUI. When
using a same-host reverse proxy, enable **Settings → General → Server Settings
→ Only listen on Localhost** and restart WireBuddy.

The public `/status` page is disabled by default. If enabled, it is restricted
to WireGuard client networks plus authenticated administrators. Treat its
connectivity details as operational telemetry.

## Keep Host Networking

WireBuddy requires Docker host networking for WireGuard interface management
and conntrack statistics. Do not weaken the startup check with
`WIREBUDDY_SKIP_NETWORK_CHECK=1` in production.

The supplied Compose service already:

- drops all Linux capabilities except `NET_ADMIN`
- enables `no-new-privileges`
- mounts only `/dev/net/tun`
- limits JSON log rotation

Keep these controls when creating overrides. The current image is not designed
to run as an arbitrary non-root UID or with a read-only root filesystem.

## Harden WireGuard

- Enable preshared keys unless interoperability requirements prevent it.
- Use non-overlapping interface networks.
- Keep peer `AllowedIPs` as narrow as the use case permits.
- Disable or delete unused peers promptly.
- Use peer isolation when clients must not communicate with one another.
- Restrict custom PostUp/PostDown scripts to reviewed administrator input.

WireGuard settings and interfaces are managed under **Settings → WireGuard**;
peers are managed from **Peers**.

## Secure DNS

Under **Settings → DNS**:

- enable DNSSEC when upstream compatibility permits it
- use validated DNS-over-TLS upstream entries
- review custom block/allow rules before applying them
- limit DNS query retention to operational needs

Retention and purge controls are under **Settings → Logs**. DNS query logs can
contain client IPs and requested domains and should be treated as sensitive.

## Limit Swagger Exposure

Swagger is disabled by default. Enable it temporarily under
**Settings → General → API Documentation** only when needed. Both `/swagger`
and `/swagger/openapi.json` require an authenticated administrator.

## Protect API Sessions

WireBuddy automation uses normal session tokens; there is no separate
long-lived API-token system.

- Send tokens only in `Authorization: Bearer ...` over HTTPS.
- Never write tokens to command history, logs, or source files.
- Reauthenticate when the session expires instead of attempting to make it
  permanent.
- Use a read-only WireBuddy user for read-only automation.

Browser session cookies are protected by CSRF validation. Do not copy browser
cookies into automation scripts.

## Back Up Safely

Use **Settings → Backup** or take a filesystem backup while the container is
stopped. Preserve:

- `docker/data/`
- the exact `WIREBUDDY_SECRET_KEY`
- any custom reverse-proxy and firewall configuration

Test restoration periodically in an isolated environment. Backup archives may
contain user records, private keys, certificates, DNS data, and optional metric
history; protect them accordingly.

## Patch and Scan

Keep the host, Docker Engine, WireBuddy image, and reverse proxy current:

```bash
docker compose --env-file .env -f docker/docker-compose.yml pull
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

Pin a full release tag when change control requires deterministic deployments.
Review the release changelog before upgrading and use an image scanner such as
Trivy or Grype in your deployment pipeline.

## Monitor Logs and Health

Monitor:

- repeated login failures and HTTP 429 responses
- password, TOTP, and passkey changes
- user, interface, peer, and node mutations
- DNS and WireGuard startup failures
- unexpected container restarts
- `/ready` failures

The built-in application does not provide an audit-log dashboard or alerting
engine. Forward Docker logs to your existing logging/SIEM platform and alert
there.

Example probes:

```bash
curl --fail --silent http://127.0.0.1:8000/health
curl --fail --silent http://127.0.0.1:8000/ready
```

## Production Checklist

- [ ] Unique 32-byte-or-longer secret key stored securely
- [ ] Bootstrap password changed
- [ ] Separate administrator accounts
- [ ] Passkey or TOTP configured for administrators
- [ ] HTTPS enabled with exact trusted-proxy CIDRs
- [ ] Host-header allowlist configured or enforced by the proxy
- [ ] GUI restricted by firewall or loopback bind
- [ ] Swagger disabled when not needed
- [ ] Only required WireGuard and DNS ports exposed
- [ ] DNS and metric retention reviewed
- [ ] Data and secret key backed up together
- [ ] Logs forwarded and health checks monitored
- [ ] Updates and restore tests scheduled

## Related

- [Security Configuration](../configuration/security.md)
- [Authentication](authentication.md)
- [Passkeys](passkeys.md)
- [Rate Limiting](rate-limiting.md)
- [Docker Setup](../getting-started/docker.md)
