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
<br>
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
| **Web UI** | Customizable drag-and-drop dashboard, responsive Bootstrap 5, dark/light/auto theme, Material Icons |

---

## Getting Started

```bash
docker pull giiibates/wirebuddy:latest
```

WireBuddy expects Linux with `network_mode: host`, a `/dev/net/tun` device and
WireGuard support in the host kernel. Set `WIREBUDDY_SECRET_KEY` (required) and
open `http://<your-server-ip>:8000`. The temporary `admin` password is printed
once to the container log (`docker logs wirebuddy`).

The default setup serves the GUI over HTTP. To use WireBuddy's built-in HTTPS,
enable **Settings → General → Serve GUI over HTTPS**, then restart the
container. It uses a self-signed certificate until you obtain a Let's Encrypt
certificate in **Settings → Let's Encrypt**.

For the Compose file, `docker run` command, environment variables, and security
setup, see the **[Documentation](https://gill-bates.github.io/wirebuddy/getting-started/docker/)**.

---

## License

Released under the [MIT License](https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE).

<p align="center">
  Maintained by <a href="https://github.com/Gill-Bates">Gill-Bates</a>
</p>
