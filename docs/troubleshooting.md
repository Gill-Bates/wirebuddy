---
title: Troubleshooting
---

# Troubleshooting

The commands below assume the repository-based setup, a root-level `.env`, and
the supplied Compose file at `docker/docker-compose.yml`.

Set a shell variable once if you are running several checks:

```bash
COMPOSE="docker compose --env-file .env -f docker/docker-compose.yml"
```

Then either use the complete commands shown below or run `$COMPOSE ps`,
`$COMPOSE logs`, and similar commands in the same shell.

## Container does not start

Check Compose validation, state, and logs:

```bash
docker compose --env-file .env -f docker/docker-compose.yml config
docker compose --env-file .env -f docker/docker-compose.yml ps
docker compose --env-file .env -f docker/docker-compose.yml logs --tail 200 wirebuddy
```

Common causes are:

- missing or shorter-than-required `WIREBUDDY_SECRET_KEY` in `.env`;
- missing `/dev/net/tun` or WireGuard host support;
- a process already listening on the GUI, WireGuard, or DNS port;
- a read-only/unwritable `docker/data/` directory; or
- unsupported Docker/Compose versions.

The container intentionally uses host networking, `/dev/net/tun`, and a
capability set of `NET_ADMIN`, `NET_BIND_SERVICE`, `SETUID`, `SETGID`, `CHOWN`,
and `DAC_OVERRIDE`. Dropping any of the last five leaves the web UI running but
breaks DNS — see [DNS does not resolve or block](#dns-does-not-resolve-or-block).

Its health endpoint is `http://127.0.0.1:8000/health` unless `WIREBUDDY_PORT`
changes the listener. Pass that variable into the container, not just into the
Compose healthcheck, or the probe and the application can target different
ports and the container stays permanently unhealthy.

## Web UI or reverse proxy

Test WireBuddy directly on the host:

```bash
curl --fail --show-error http://127.0.0.1:8000/health
ss -ltnp | grep ':8000'
```

If direct access works but the proxy returns `502`, verify the upstream address
and that **Only listen on Localhost** matches the deployment. For authentication
or CSRF problems behind a proxy, verify:

- `WIREBUDDY_TRUST_PROXY_HEADERS=1` only when a trusted proxy is in use;
- `FORWARDED_ALLOW_IPS` identifies only that proxy;
- `WIREBUDDY_PUBLIC_ORIGIN` matches the browser-visible origin; and
- `WIREBUDDY_CSRF_ALLOWED_ORIGINS` contains any additional trusted origins.

Clear stale site cookies after changing origins. Session lifetimes are fixed at
one hour idle and 24 hours absolute; there is no session-timeout UI setting.

## Built-in HTTPS

These apply when **Settings → General → Serve GUI over HTTPS** is enabled. The
setting is read at startup, so every change needs a restart.

### Browser warns the certificate is not trusted

WireBuddy is serving the self-signed fallback, because no valid Let's Encrypt
certificate exists for the configured Server FQDN. Check which one is active:

```bash
echo | openssl s_client -connect 127.0.0.1:8000 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

An issuer of `O=WireBuddy` is the self-signed fallback. Request a certificate in
**Settings → Let's Encrypt** and restart. The Settings page also shows which
certificate would be served.

### Certificate was issued but the old one is still served

Certificates are read only at startup. Restart WireBuddy. There is no automated
renewal job — see [Let's Encrypt](features/acme.md#with-the-built-in-https-listener).

### Let's Encrypt validation fails while HTTPS is on

HTTP-01 always validates over plain HTTP on port 80. WireBuddy runs a plaintext
listener for that, but it must be reachable from the internet:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  http://DOMAIN/.well-known/acme-challenge/test
```

`404` is the healthy answer for an unknown token — it proves the listener is
reachable. A timeout or TLS error means port 80 does not reach it. If the log
shows `Could not bind plaintext ACME listener`, the port is taken or the
container lacks `NET_BIND_SERVICE`; HTTPS still runs, only validation is
affected. Set `gui_acme_http_port` to `0` if another service owns port 80.

### Login is rejected with "requires HTTPS"

Expected: with HTTPS enabled, logins and node enrollments over plain HTTP are
refused so credentials are never sent in clear text. Reach the GUI over
`https://`. Behind a reverse proxy that terminates TLS, leave this setting off
and let the proxy handle TLS.

### Node cannot enroll over HTTPS

A node rejecting the master's self-signed certificate must either trust it or
enroll against a master using a Let's Encrypt certificate. The master log shows
the rejected enrollment.

## Peer cannot handshake

Verify the interface and endpoint:

```bash
sudo wg show
sudo ss -lunp | grep ':51820'
```

Check that:

1. the interface is active under **Settings → WireGuard**;
2. the client configuration contains the current server FQDN/IP and UDP port;
3. all host, router, and cloud firewalls allow that UDP port;
4. the client and server clocks are synchronized; and
5. the client has the current keys and preshared key.

After changing endpoint, routing, DNS, or PSK settings, download or scan the
client configuration again.

## Tunnel connects but has no internet

Check forwarding and NAT on the host:

```bash
sysctl net.ipv4.ip_forward
sudo iptables -t nat -L POSTROUTING -n -v
sudo iptables -L FORWARD -n -v
```

`net.ipv4.ip_forward` must be `1`. Newly created interfaces receive generated
masquerade and forwarding hooks when no custom hooks are supplied. If custom
hooks were configured, verify that their outbound interface and VPN subnet match
the current host. Also confirm that the peer's routing mode includes the intended
destinations.

## DNS does not resolve or block

Check the DNS page and service state first. The Docker image includes Unbound;
local source installations must install it separately.

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy | grep -i unbound
dig @10.13.13.1 example.com
```

Verify the queried address is the selected interface's address, the peer has
**Use Ad-blocking DNS (WireBuddy)** enabled, and at least one global blocklist is
enabled under **Settings → DNS**. Select **Update Blocklists** after changing
sources. Per-peer list selection and DNS logging are configured in the peer form.

For DNSSEC issues, verify that the image's `/var/lib/unbound/root.key` exists and
that the upstream DNS-over-TLS hostnames and port 853 are reachable.

### `Permission denied: '/var/log/unbound/queries.log'`

The container's capability set is incomplete. `cap_drop: ALL` also removes
root's `DAC_OVERRIDE`, so normal file permissions apply to uid 0 — and
`/var/log/unbound` is owned by `unbound:unbound`. Writing the config aborts,
Unbound never starts, and the web UI comes up without DNS.

Related failures from the same cause, visible in the container log:

| Log line | Missing capability |
|----------|--------------------|
| `PermissionError: ... '/var/log/unbound/queries.log'` | `DAC_OVERRIDE` |
| `fatal error: unable to set group id of unbound` | `SETUID`, `SETGID` |
| `Could not open logfile ...` (Unbound runs, query log stays empty) | `CHOWN` |
| `can't bind socket` on port 53 | `NET_BIND_SERVICE` |

Compare the running container against the shipped Compose file:

```bash
docker inspect wirebuddy --format '{{.HostConfig.CapAdd}}'
```

It must list all six capabilities. Recreate the container after correcting them;
`docker compose restart` does not apply capability changes.

### `Port conflict: UDP <address>:53 is already in use`

Unbound binds only the WireGuard gateway addresses, never `127.0.0.1`, so
`systemd-resolved` on `127.0.0.53` does not conflict with it. A conflict means
another resolver holds the same address — or a wildcard bind on `0.0.0.0:53`
that covers it. Identify the holder on the host:

```bash
ss -lntupn 'sport = :53'
```

Let `ss` filter by port rather than piping into `grep -w ':53'` — the `-w` flag
never matches, because the character preceding `:53` in an address such as
`10.13.13.1:53` is a word character, so every match is rejected.

!!! note "Host networking has no separate port namespace"
    With `network_mode: host` the container shares the host's network stack.
    Port 53 *is* the host's port 53; the `EXPOSE 53/udp` line in the image is
    documentation only and allocates nothing.

## Traffic or GeoIP analytics are empty

WireGuard counters require an active interface and handshakes. Country and ASN
destination analytics additionally require **Settings → WireGuard → Country
Traffic Analysis** and conntrack byte accounting:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
cat /proc/sys/net/netfilter/nf_conntrack_acct
ls -lh docker/data/geolite2/
```

Sampling runs every 30 seconds, so new data is not instantaneous. Check GeoIP
download/update messages if the databases are absent:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy | grep -i geoip
```

Retention is configured under **Settings → Logs**. There is no `/api/metrics/*`
endpoint, metrics export, or configurable sampling interval in the current
release.

## Database checks and backups

The host database path for the supplied Compose file is
`docker/data/wirebuddy.db`. Stop WireBuddy before running an offline SQLite
integrity check so the result is unambiguous:

```bash
docker compose --env-file .env -f docker/docker-compose.yml stop wirebuddy
sqlite3 docker/data/wirebuddy.db 'PRAGMA integrity_check;'
docker compose --env-file .env -f docker/docker-compose.yml start wirebuddy
```

An `ok` result indicates that SQLite found no corruption. Restore configuration
through **Settings → Backup** using a backup produced by the current backup
format. Keep the same `WIREBUDDY_SECRET_KEY`; backup integrity verification is
derived from it.

!!! warning
    Do not delete, replace, or directly edit `wirebuddy.db` as a routine repair.
    Make a byte-for-byte offline copy before any expert-level recovery work.

## Login, TOTP, and passkeys

TOTP depends on accurate time. Use one of the eight recovery codes if the
authenticator is unavailable. An administrator can manage another account's
password, TOTP requirement, and passkey requirement from **Users**.

The current release has no standalone `app.utils.reset_password` command and no
supported unauthenticated admin-reset flow. If the only administrator is locked
out, preserve `docker/data/` and `.env`, then seek recovery help rather than
running undocumented database updates.

Passkeys require a secure, stable browser origin: HTTPS for non-localhost hosts,
with matching WebAuthn RP/origin settings when the automatic values are not
suitable. Password login remains the fallback unless policy requires passkey
setup.

## Let’s Encrypt failures

HTTP-01 requires public DNS and inbound TCP/80. Ensure the reverse proxy forwards
`/.well-known/acme-challenge/` to WireBuddy. Use the staging checkbox while
testing to avoid production rate limits.

Certificates are stored under `docker/data/certs/`. WireBuddy does not
automatically renew them or configure/reload your reverse proxy; see
[Let’s Encrypt](features/acme.md).

## Collect information for a bug report

Include the WireBuddy version, Docker and Compose versions, host OS, browser (for
UI issues), exact reproduction steps, and a focused log excerpt. Remove secrets,
session cookies, passwords, private keys, preshared keys, enrollment tokens, and
publicly sensitive addresses before posting logs.

Search or open an issue at the
[WireBuddy issue tracker](https://github.com/Gill-Bates/wirebuddy/issues).
