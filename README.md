<p align="center">
  <img src=".github/img/wirebuddy_black.svg#gh-light-mode-only" width="400">
  <img src=".github/img/wirebuddy_white.svg#gh-dark-mode-only" width="400">
</p>

<h2 align="center">Use Wireguard with ease!</h2>

<p align="center">
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/v/giiibates/wirebuddy?label=Docker%20Hub&logo=docker&logoColor=white" alt="Docker Hub"></a>
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/pulls/giiibates/wirebuddy?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/image-size/giiibates/wirebuddy/latest?logo=docker&logoColor=white" alt="Docker Image Size"></a>
  <br>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Platform-linux%2Famd64%20|%20linux%2Farm64-lightgrey?logo=linux&logoColor=white" alt="Platform"></a>
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-configuration">Configuration</a> •
  <a href="#-security">Security</a> •
  <a href="#-license">License</a>
</p>

---

## 🚀 Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy

# Copy and edit settings
cp .env-example settings.env
# Edit settings.env — set WIREBUDDY_SECRET_KEY!

# Run
docker compose up -d
```

The default compose file expects an external Docker network (`cloudnet`) and
does not expose port 8000. To access the UI directly, add `8000:8000` under
`ports` or place the container behind your reverse proxy.

> **Default credentials:** `admin` / `admin`
> ⚠️ **Change the default password immediately after first login!**

### Screenshots

<p align="center">
  <img src=".github/img/screen1.png" alt="Dashboard" width="100%" style="border-radius: 12px; margin-bottom: 16px;">
</p>
<p align="center">
  <img src=".github/img/screen2.png" alt="Peers" width="100%" style="border-radius: 12px; margin-bottom: 16px;">
</p>
<p align="center">
  <img src=".github/img/screen3.png" alt="DNS Ad-Blocker" width="100%" style="border-radius: 12px;">
</p>

### Local Development

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## ✨ Features

| Category | Highlights |
|---|---|
| 🔒 **WireGuard VPN** | Multi-interface management, automatic keypair generation, routing presets (Full Tunnel / Isolated / Custom), QR codes for mobile setup |
| 🌍 **DNS Ad-Blocking** | Integrated Unbound resolver with blocklists (StevenBlack, EasyList), DNS-over-TLS, real-time query log, DNSSEC |
| 📊 **Monitoring** | Built-in time-series database, per-peer traffic charts, connection status dashboard, auto-refresh |
| 🗺️ **GeoIP** | MaxMind GeoLite2 integration, interactive map with heatmap, country flags & ASN badges |
| 🔐 **Let's Encrypt** | Built-in ACME client with HTTP-01 challenge, certificate management UI |
| 👥 **User Management** | Multi-user roles (admin/user), login tracking, token lifecycle |
| 🎨 **Web UI** | Responsive Bootstrap 5, dark/light/auto theme, Material Icons |

---

## ⚙️ Configuration

Environment variables (via `settings.env` or Docker env):

| Variable | Default | Description |
|---|---|---|
| `WIREBUDDY_SECRET_KEY` | *(required)* | Encryption key for secrets & sessions |
| `WIREBUDDY_DATA_DIR` | `/data` | Persistent data directory |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 🛡️ Security

| Layer | Implementation |
|---|---|
| **Passwords** | PBKDF2-SHA256, 600 000 iterations, random salt |
| **Secrets at rest** | Fernet encryption (PBKDF2 + per-row salt + app pepper) |
| **Auth tokens** | SHA-256 hashed before storage, expiry enforced |
| **CSRF** | Double-submit cookie + Origin header validation |
| **Brute-force** | Rate limiting + progressive IP lockout with backoff |
| **Proxy trust** | `X-Forwarded-For` only accepted from configured proxies |
| **Input validation** | Strict regex for interface names; Pydantic for all payloads |
| **Container** | `no-new-privileges`, minimal capabilities (`NET_ADMIN`) |

---

## 📝 License

This project is licensed under the **GNU Affero General Public License v3.0** — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ☕ by <a href="https://github.com/Gill-Bates">Gill-Bates</a> | © 2026
</p>
