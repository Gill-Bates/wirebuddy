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

The container intentionally uses host networking, `NET_ADMIN`, and
`/dev/net/tun`. Its health endpoint is `http://127.0.0.1:8000/health` unless
`WIREBUDDY_PORT` changes the listener.

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
