<p align="center">
  <img src="https://github.com/Gill-Bates/wirebuddy/raw/main/app/static/img/wirebuddy_1c.svg" width="400">
<br>
Use WireGuard with ease!
</p>

<p align="center">
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/v/giiibates/wirebuddy?label=Docker%20Hub&logo=docker&logoColor=white" alt="Docker Hub"></a>
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/pulls/giiibates/wirebuddy?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/image-size/giiibates/wirebuddy/latest?logo=docker&logoColor=white" alt="Docker Image Size"></a>
  <br>
  <a href="https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="#quick-start"><img src="https://img.shields.io/badge/Platform-linux%2Famd64%20|%20linux%2Farm64-lightgrey?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://gill-bates.github.io/wirebuddy/"><img src="https://img.shields.io/badge/Docs-Online-green?logo=readthedocs&logoColor=white" alt="Documentation"></a>
</p>

<p align="center">
  <a href="https://gill-bates.github.io/wirebuddy/">Documentation</a> •
  <a href="https://gill-bates.github.io/wirebuddy/getting-started/quick-start/">Quick Start</a> •
  <a href="https://github.com/Gill-Bates/wirebuddy">GitHub</a>
</p>

---

A complete self-hosted VPN solution with web-based management, integrated Unbound DNS resolver, ad-blocking, real-time traffic analytics, and GeoIP visualization.

## Features

| Category | Highlights |
|---|---|
| **WireGuard VPN** | Multi-interface management, automatic keypair generation, routing presets, QR codes for mobile setup |
| **DNS Ad-Blocking** | Integrated Unbound resolver with blocklists, DNS-over-TLS, real-time query log, DNSSEC, client-scoped rules |
| **Monitoring** | Built-in time-series database, per-peer traffic charts, traffic analysis by country & ASN |
| **GeoIP** | MaxMind GeoLite2 integration, interactive heatmap, country flags & ASN badges |
| **Let's Encrypt** | Built-in ACME client with HTTP-01 challenge, certificate management UI |
| **User Management** | Multi-user roles, Passkeys (WebAuthn) & MFA (TOTP), login tracking |
| **Web UI** | Responsive Bootstrap 5, dark/light/auto theme, Material Icons |

---

## Quick Start

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
  -e WIREBUDDY_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" \
  -e WIREBUDDY_TRUST_PROXY_HEADERS=1 \
  -v wirebuddy-data:/app/data \
  giiibates/wirebuddy:latest
```

Then open `http://<your-server-ip>:8000` in your browser.

If you run WireBuddy behind Caddy, nginx, or another reverse proxy on the same
host, leave `WIREBUDDY_TRUST_PROXY_HEADERS=1` enabled so HTTPS origin checks use
the forwarded scheme correctly. If the proxy connects from a different IP or
container network, also set `FORWARDED_ALLOW_IPS` to that proxy IP or CIDR.

On first boot of a new database, WireBuddy automatically creates a bootstrap `admin` user with a randomly generated temporary password. The password is printed to the container log — check `docker logs wirebuddy` after the first start to retrieve it. You will be prompted to set a permanent password on the first login.

---

## Docker Compose

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    container_name: wirebuddy
    restart: always
    stop_grace_period: 20s
    network_mode: host
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      LOG_LEVEL: INFO
      TZ: Etc/UTC
      WIREBUDDY_SECRET_KEY: ""  # Generate with: head -c 32 /dev/urandom | base64
      WIREBUDDY_TRUST_PROXY_HEADERS: "1"
      # If your reverse proxy is not on 127.0.0.1, set its IP or CIDR here.
      # FORWARDED_ALLOW_IPS: "127.0.0.1,172.18.0.0/16"
      WIREBUDDY_DATA_DIR: /app/data
    volumes:
      - ./data:/app/data
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
    security_opt:
      - no-new-privileges:true
    healthcheck:
      test: ["CMD", "curl", "--fail", "--silent", "--max-time", "5", "http://127.0.0.1:${WIREBUDDY_PORT:-8000}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WIREBUDDY_SECRET_KEY` | **Yes** | — | Encryption key for database secrets. Generate with: `head -c 32 /dev/urandom \| base64` |
| `LOG_LEVEL` | No | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `WIREBUDDY_PORT` | No | `8000` | HTTP port for the web UI |
| `WIREBUDDY_TRUST_PROXY_HEADERS` | No | `1` in Docker entrypoint | Trust `X-Forwarded-*` headers from `FORWARDED_ALLOW_IPS` so CSRF and origin checks work behind HTTPS reverse proxies |
| `FORWARDED_ALLOW_IPS` | No | `127.0.0.1` | Comma-separated proxy IPs or CIDRs whose forwarded headers may be trusted |
| `TZ` | No | Container default | Time zone used for logs and scheduled tasks |
| `WIREBUDDY_DATA_DIR` | No | `/app/data` | Base directory for persistent application data inside the container |
| `WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS` | No | — | Comma-separated CIDRs for trusted reverse proxies |

> Important: Keep `WIREBUDDY_SECRET_KEY` secure and consistent across container recreations. Losing this key means losing access to encrypted WireGuard private keys.

---

## Volumes

| Path | Description |
|------|-------------|
| `/app/data` | Persistent data (SQLite database, certificates, DNS configs, TSDB) |

---

## Requirements

- **Host network mode** (`--network host`) — Required for WireGuard to manage network interfaces
- **NET_ADMIN capability** — Required for creating WireGuard interfaces
- **TUN device** (`/dev/net/tun`) — Required for VPN tunnels
- Linux host with kernel 5.6+ (WireGuard built-in) or wireguard-dkms installed

---

## Documentation

For complete installation guides, configuration options, API reference, and troubleshooting:

**[gill-bates.github.io/wirebuddy](https://gill-bates.github.io/wirebuddy/)**

---

## License

**GNU Affero General Public License v3.0** — see [LICENSE](https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE) for details.

---

<p align="center">
  Maintained by <a href="https://github.com/Gill-Bates">Gill-Bates</a>
</p>