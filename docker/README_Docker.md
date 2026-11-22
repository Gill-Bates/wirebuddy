<p align="center">
  <img src="https://github.com/Gill-Bates/wirebuddy/raw/main/app/static/img/wirebuddy_1c.svg" width="400">
<br>
Use WireGuard with ease!
</p>

[![Docker Pulls](https://img.shields.io/docker/pulls/giiibates/wirebuddy?logo=docker&logoColor=white)](https://hub.docker.com/r/giiibates/wirebuddy)
![Platforms](https://img.shields.io/badge/Platform-linux%2Famd64%20%7C%20linux%2Farm64-lightgrey?logo=linux&logoColor=white)

---

A complete self-hosted VPN solution with web-based management, integrated Unbound DNS resolver, ad-blocking, real-time traffic analytics, and GeoIP visualization.

![WireBuddy dashboard: nodes, connections, traffic, bandwidth, peer locations map, and speedtest history](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_2.jpeg)

*Dashboard — network status, peer locations, and speedtest history at a glance.*

### More screenshots

![WireBuddy login screen](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_1.jpeg)

*Login — Auto/Light/Dark theme toggle, no account enumeration on failed attempts.*

![WireBuddy traffic page: per-peer chart plus destination breakdown by country and ASN](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_3.jpeg)

*Traffic — per-peer RX/TX charts with destination breakdown by country and ASN.*

![WireBuddy DNS ad-blocking: query stats, top blocked domains, block-rate trend, and live query log](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_4.jpeg)

*DNS ad-blocking — live query log, top blocked domains, and block-rate trend.*

![WireBuddy WireGuard settings: global MTU/keepalive/PSK options, interfaces, and traffic analysis toggle](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_5.jpeg)

*WireGuard Settings — global tunnel defaults, interface management, and traffic analysis.*

![WireBuddy logs settings: retention sliders and storage stats for traffic, DNS, peer, and speedtest metrics](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen_6.jpeg)

*Logs — per-dataset retention and storage stats, with one-click purge.*

## Features

| Category | Highlights |
|---|---|
| **WireGuard VPN** | Multi-interface management, automatic keypair generation, routing presets, client isolation, QR codes for mobile setup |
| **Multi-Node** | Distributed VPN clusters, automatic peer synchronization, metrics aggregation, and token-based enrollment |
| **DNS Ad-Blocking** | Integrated Unbound resolver with blocklists, DNS-over-TLS, real-time query log, DNSSEC, client-scoped rules |
| **Monitoring** | Built-in time-series database, per-peer traffic charts, traffic analysis by country & ASN |
| **GeoIP** | MaxMind GeoLite2 integration, interactive heatmap, country flags & ASN badges |
| **HTTPS & Certificates** | Built-in HTTPS with self-signed or Let's Encrypt certificates, HTTP-01 validation, and certificate management |
| **User Management** | Multi-user roles, Passkeys (WebAuthn) & two-factor authentication (2FA, TOTP), login tracking |
| **Web UI** | Customizable drag-and-drop dashboard, responsive Bootstrap 5, dark/light/auto theme, Material Icons |

---

## Getting Started

```bash
docker pull giiibates/wirebuddy:latest
```

WireBuddy expects Linux with `network_mode: host` and WireGuard support in the
host kernel. Set `WIREBUDDY_SECRET_KEY` (required) and
open `http://<your-server-ip>:8000`. The temporary `admin` password is printed
once to the container log (`docker logs wirebuddy`).

The default setup serves the GUI over HTTP. To use WireBuddy's built-in HTTPS,
enable **Settings → General → Serve GUI over HTTPS**, then restart the
container. It uses a self-signed certificate until you obtain a Let's Encrypt
certificate in **Settings → Let's Encrypt**, and falls back to it whenever that
certificate is expired, not yet valid, or does not cover the host name.

For the Compose file, `docker run` command, environment variables, and security
setup, see the **[Documentation](https://gill-bates.github.io/wirebuddy/getting-started/docker/)**.

---

## License

Released under the [MIT License](https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE).

Maintained by [Gill-Bates](https://github.com/Gill-Bates).
