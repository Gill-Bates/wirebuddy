---
title: Docker Setup
---

# Docker Setup Guide

WireBuddy's supported container deployment uses Docker host networking on a
Linux host. The repository contains the master Compose file at
`docker/docker-compose.yml` and the node Compose file at
`docker/docker-compose.node.yml`.

## Prerequisites

- Linux host (amd64 or arm64)
- Docker Engine and Docker Compose
- WireGuard support in the host kernel (Linux 5.6+ or a compatible module)
- `/dev/net/tun`
- IP forwarding enabled on the host

Containers share the host kernel. The image therefore supplies `wg` and
`wg-quick`, but it cannot supply the WireGuard kernel implementation.

## Docker Compose

Clone the repository and create the environment file:

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
cp .env-example .env
```

Generate a key and store it as `WIREBUDDY_SECRET_KEY` in `.env`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

The key must contain at least 32 UTF-8 bytes. Keep it unchanged across
container recreations; changing or losing it makes encrypted WireGuard and OTP
secrets unreadable.

Start WireBuddy from the repository root:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

View the bootstrap password and startup status:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs -f wirebuddy
```

Open `http://<server-ip>:8000` and sign in as `admin` with the generated
temporary password from the log. The first login requires a password change.

!!! note "Why the full Compose command?"
    The Compose file lives in `docker/`, while `.env` lives in the repository
    root. Passing both paths explicitly makes configuration resolution
    independent of the current working directory.

## Included Compose Security

The supplied Compose service uses:

- `network_mode: host`
- all capabilities dropped except `NET_ADMIN`
- `no-new-privileges:true`
- `/dev/net/tun`
- a 20-second stop grace period
- bounded JSON-file log rotation
- a liveness health check against `/health`

Do not switch the service to bridge or macvlan networking. WireBuddy verifies
host networking at startup because interface management and conntrack
statistics require the host network namespace.

`WIREBUDDY_SKIP_NETWORK_CHECK=1` is a development/CI escape hatch, not a
production setting.

## Persistent Data

The Compose file mounts `docker/data/` at `/app/data` in the container.

| Path | Content |
|---|---|
| `wirebuddy.db` | Users, interfaces, peers, settings, and node state |
| `certs/` | ACME certificates and account material |
| `dns/` | Generated Unbound configuration and DNS query data |
| `tsdb/` | Traffic, DNS trend, network, and speed-test metrics |
| `geolite2/` | Downloaded GeoLite2 City and ASN databases |

Back up both `docker/data/` and the secret key. The application also provides
backup and restore controls under **Settings → Backup**.

## Custom Web Port or Bind Address

The GUI port and localhost-only setting are normally managed under
**Settings → General → Server Settings** and take effect after restart.

Docker deployments can override them in `.env`:

```bash
WIREBUDDY_HOST=0.0.0.0
WIREBUDDY_PORT=8080
```

Because host networking is used, no Docker `ports:` mapping is required. The
selected port must be free on the host.

## Reverse Proxy

The Docker entrypoint trusts forwarded headers from loopback by default. For a
same-host Caddy or nginx proxy, keep:

```bash
WIREBUDDY_TRUST_PROXY_HEADERS=1
FORWARDED_ALLOW_IPS=127.0.0.1
```

If the proxy connects from another address, replace or extend
`FORWARDED_ALLOW_IPS` with the exact proxy IP or CIDR. A wildcard (`*`) is
rejected. Also configure the application-level trusted proxy range used for
client-IP and HTTPS-cookie detection:

```bash
TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128
WIREBUDDY_PUBLIC_ORIGIN=https://vpn.example.com
```

See [Environment Variables](../configuration/environment.md) and the
[Installation Guide](installation.md#reverse-proxy) for complete proxy
examples.

## Docker Run

Compose is recommended. An equivalent basic container can be started with:

```bash
docker run -d \
  --name wirebuddy \
  --network host \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  --stop-timeout 20 \
  --device /dev/net/tun:/dev/net/tun \
  -e TZ=Etc/UTC \
  -e WIREBUDDY_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  -e WIREBUDDY_DATA_DIR=/app/data \
  -v wirebuddy-data:/app/data \
  --restart always \
  giiibates/wirebuddy:latest
```

Persist the generated secret separately before relying on this example for a
production installation.

## Health Checks

Two unauthenticated probes are available:

- `/health`: lightweight liveness check
- `/ready`: readiness including database, scheduler, and expected DNS
  ingestion state

The supplied Compose file uses `/health`. External orchestration should prefer
`/ready` when it must wait until application services are operational.

## Updating

```bash
docker compose --env-file .env -f docker/docker-compose.yml pull
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

Use `latest` for the current stable release or pin an existing full release
tag from [Docker Hub](https://hub.docker.com/r/giiibates/wirebuddy/tags).

## Managing the Container

```bash
# Status
docker compose --env-file .env -f docker/docker-compose.yml ps

# Restart
docker compose --env-file .env -f docker/docker-compose.yml restart wirebuddy

# Shell
docker compose --env-file .env -f docker/docker-compose.yml exec wirebuddy bash

# WireGuard status
docker compose --env-file .env -f docker/docker-compose.yml exec wirebuddy wg show
```

## Remote Node

Remote nodes use `docker/docker-compose.node.yml` and an enrollment token plus
verification key created by the master. Follow the
[Multi-Node Deployment](../features/multi-node.md) guide rather than adapting
the master Compose service.

## Troubleshooting

If the container exits during startup:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy
docker compose --env-file .env -f docker/docker-compose.yml config
docker inspect wirebuddy --format '{{.HostConfig.NetworkMode}}'
```

The final command must print `host`. Also verify that `/dev/net/tun` exists,
the configured GUI port is free, and the secret key has at least 32 bytes.

## Next Steps

- [First Steps](first-steps.md)
- [Environment Variables](../configuration/environment.md)
- [Security Best Practices](../security/best-practices.md)
