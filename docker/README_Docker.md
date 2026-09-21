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
  <a href="https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
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

<p align="center">
  <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_2.jpeg" alt="WireBuddy dashboard: nodes, connections, traffic, bandwidth, peer locations map, and speedtest history" width="800"><br>
  <em>Dashboard — network status, peer locations, and speedtest history at a glance.</em>
</p>

<details>
  <summary align="center"><b>More screenshots</b></summary>
  <br>
  <p align="center">
    <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_1.jpeg" alt="WireBuddy login screen" width="800"><br>
    <em>Login — dark/light theme toggle, no account enumeration on failed attempts.</em>
  </p>
  <p align="center">
    <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_3.jpeg" alt="WireBuddy traffic page: per-peer chart plus destination breakdown by country and ASN" width="800"><br>
    <em>Traffic — per-peer RX/TX charts with destination breakdown by country and ASN.</em>
  </p>
  <p align="center">
    <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_4.jpeg" alt="WireBuddy DNS ad-blocker: query stats, top blocked domains, block-rate trend, and live query log" width="800"><br>
    <em>DNS Ad-Blocker — live query log, top blocked domains, and block-rate trend.</em>
  </p>
  <p align="center">
    <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_5.jpeg" alt="WireBuddy WireGuard settings: global MTU/keepalive/PSK options, interfaces, and traffic analysis toggle" width="800"><br>
    <em>WireGuard Settings — global tunnel defaults, interface management, and traffic analysis.</em>
  </p>
  <p align="center">
    <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_6.jpeg" alt="WireBuddy logs settings: retention sliders and storage stats for traffic, DNS, peer, and speedtest metrics" width="800"><br>
    <em>Logs — per-dataset retention and storage stats, with one-click purge.</em>
  </p>
</details>

## Features

| Category | Highlights |
|---|---|
| **WireGuard VPN** | Multi-interface management, automatic keypair generation, routing presets, client isolation, QR codes for mobile setup |
| **Multi-Node** | Distributed VPN clusters, automatic peer synchronization, metrics aggregation, and token-based enrollment |
| **DNS Ad-Blocking** | Integrated Unbound resolver with blocklists, DNS-over-TLS, real-time query log, DNSSEC, client-scoped rules |
| **Monitoring** | Built-in time-series database, per-peer traffic charts, traffic analysis by country & ASN |
| **GeoIP** | MaxMind GeoLite2 integration, interactive heatmap, country flags & ASN badges |
| **HTTPS & Certificates** | Built-in HTTPS with self-signed or Let's Encrypt certificates, HTTP-01 validation, and certificate management |
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
  --cap-add NET_BIND_SERVICE \
  --cap-add SETUID \
  --cap-add SETGID \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --security-opt no-new-privileges:true \
  --stop-timeout 40 \
  --device /dev/net/tun:/dev/net/tun \
  -e TZ=Etc/UTC \
  -e WIREBUDDY_SECRET_KEY="$(head -c 32 /dev/urandom | base64)" \
  -v wirebuddy-data:/app/data \
  giiibates/wirebuddy:latest
```

Then open `http://<your-server-ip>:8000` in your browser.

This quick start serves the GUI over HTTP. To use WireBuddy's built-in HTTPS,
enable **Settings → General → Serve GUI over HTTPS**, then restart the
container. WireBuddy uses a self-signed certificate until you obtain a Let's
Encrypt certificate in **Settings → Let's Encrypt**.

WireBuddy trusts forwarded headers (`X-Forwarded-*`) from loopback
(`127.0.0.1`, `::1`) by default, so a reverse proxy on the same host (Caddy,
nginx) works out of the box for HTTPS origin checks. If your proxy connects
from a different IP or container network, set `WIREBUDDY_TRUSTED_PROXIES` to
that proxy's IP(s) or CIDR(s).

On first boot of a new database, WireBuddy automatically creates a bootstrap `admin` user with a randomly generated temporary password. The password is printed to the container log — check `docker logs wirebuddy` after the first start to retrieve it. You will be prompted to set a permanent password on the first login.

---

## Docker Compose

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    container_name: wirebuddy
    restart: always
    stop_grace_period: 40s
    network_mode: host
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN          # WireGuard interfaces, iptables/nft rules
      - NET_BIND_SERVICE   # Unbound binds the privileged DNS port 53
      - SETUID             # Unbound drops privileges to the 'unbound' user
      - SETGID
      - CHOWN              # hands the DNS query log to that user
      - DAC_OVERRIDE       # root writes into the unbound-owned log directory
    devices:
      - /dev/net/tun:/dev/net/tun
    environment:
      LOG_LEVEL: INFO
      TZ: Etc/UTC
      WIREBUDDY_SECRET_KEY: ""  # Generate with: head -c 32 /dev/urandom | base64
      WIREBUDDY_PORT: "8000"   # must match the healthcheck URL below
      # Trusted reverse-proxy IPs/CIDRs. Defaults to loopback; extend if your
      # proxy is not on 127.0.0.1 (e.g. a separate container network).
      WIREBUDDY_TRUSTED_PROXIES: "127.0.0.1,::1"
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
| `WIREBUDDY_PUBLIC_ORIGIN` | No | — | Canonical public URL (e.g. `https://vpn.example.com`). Derives CSRF origins, passkey origin, Host-header allowlist and secure cookies/HSTS for `https://` |
| `WIREBUDDY_TRUSTED_PROXIES` | No | `127.0.0.1,::1` | Comma-separated proxy IPs or CIDRs trusted for both uvicorn's forwarded headers and app-level proxy-trust checks (CSRF/origin, client-IP resolution) |
| `TZ` | No | Container default | Time zone used for logs and scheduled tasks |
| `WIREBUDDY_DATA_DIR` | No | `/app/data` | Base directory for persistent application data inside the container |

> Important: Keep `WIREBUDDY_SECRET_KEY` secure and consistent across container recreations. Losing this key means losing access to encrypted WireGuard private keys.

---

## Volumes

| Path | Description |
|------|-------------|
| `/app/data` | Persistent data (SQLite database, certificates, DNS configs, TSDB) |

---

## Requirements

- **Host network mode** (`--network host`) — Required for WireGuard to manage network interfaces
- **Capabilities** — `NET_ADMIN` for WireGuard interfaces and iptables rules. With `--cap-drop ALL` the DNS resolver additionally needs `NET_BIND_SERVICE`, `SETUID`, `SETGID`, `CHOWN`, and `DAC_OVERRIDE`; without a full drop, Docker's default set already covers those
- **TUN device** (`/dev/net/tun`) — Required for VPN tunnels
- Linux host with kernel 5.6+ (WireGuard built in) or a compatible WireGuard kernel module installed on the host

### GUI port and health check

The container health check probes `WIREBUDDY_PORT` (default `8000`). If you
change the GUI port only in **Settings → General** (persisted as `gui_port` in
the database) without also setting `WIREBUDDY_PORT`, the entrypoint binds to
the new port but the health check keeps probing the old one and the container
is reported unhealthy. Set `WIREBUDDY_PORT` to match whenever you change the
GUI port.

### WireGuard source policy

The image builds `wg` and `wg-quick` from the current `master` branch of the official
[`wireguard-tools`](https://git.zx2c4.com/wireguard-tools/) repository whenever the image is built.
The Debian `wireguard`, `wireguard-tools`, and `wireguard-dkms` packages are pinned with APT priority `-1`
and cannot be installed into the image.

Containers share the host kernel, so an upstream Linux kernel module cannot be baked into a portable image.
The host must provide the WireGuard implementation. Rebuild the image to pick up newer upstream
`wireguard-tools` revisions.

---

## Documentation

For complete installation guides, configuration options, API reference, and troubleshooting:

**[gill-bates.github.io/wirebuddy](https://gill-bates.github.io/wirebuddy/)**

---

## License

**MIT License** — see [LICENSE](https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE) for details.

---

<p align="center">
  Maintained by <a href="https://github.com/Gill-Bates">Gill-Bates</a>
</p>
