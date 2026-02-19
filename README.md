<p align="center">
  <img src="app/static/img/wirebuddy_1c.svg" alt="WireBuddy Logo" width="400">
</p>


<p align="center">
  <a href="https://github.com/Gill-Bates/wirebuddy/releases/latest"><img src="https://img.shields.io/github/v/release/Gill-Bates/wirebuddy?style=flat-square&color=blue" alt="Latest Release"></a>
  <a href="https://github.com/Gill-Bates/wirebuddy/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-green?style=flat-square" alt="License"></a>
  <a href="https://hub.docker.com/r/gillbates/wirebuddy"><img src="https://img.shields.io/docker/pulls/gillbates/wirebuddy?style=flat-square&color=blue" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/gillbates/wirebuddy"><img src="https://img.shields.io/docker/image-size/gillbates/wirebuddy/latest?style=flat-square&label=image%20size" alt="Docker Image Size"></a>
  <img src="https://img.shields.io/badge/python-3.13-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.13">
  <img src="https://img.shields.io/badge/platform-amd64%20%7C%20arm64-lightgrey?style=flat-square" alt="Platforms">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-configuration">Configuration</a> •
  <a href="#-api">API</a> •
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
cp settings.env.example settings.env
# Edit settings.env — set WIREBUDDY_SECRET_KEY!

# Build and run
docker compose up -d
```

Open **http://localhost:8000** — done.

> **Default credentials:** `admin` / `admin`
> ⚠️ **Change the default password immediately after first login!**

### Local Development

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

## ✨ Features

### 🔒 WireGuard VPN Management

- **Multi-interface support** — create, start, stop, and delete multiple WireGuard interfaces
- **Full peer lifecycle** — add, edit, remove peers with automatic IP allocation
- **Automatic keypair & PSK generation** — including post-quantum preshared keys
- **Routing presets** — Full Tunnel, Isolated (no LAN), or Custom CIDR ranges
- **QR codes & config downloads** — one-tap mobile setup
- **Config persistence** — configs rebuild from database on every container restart
- **Auto-start & graceful shutdown** — interfaces come up on boot and shut down cleanly

### 🌍 DNS & Ad-Blocking (Unbound)

- **Integrated Unbound DNS resolver** — start, stop, restart, reload from the UI
- **Ad-blocking with blocklists** — StevenBlack/hosts, AdAway, and custom sources; auto-updated every 24 h
- **Wildcard subdomain blocking** — optionally block all subdomains of blocked domains
- **DNS-over-TLS upstream** — configurable upstream servers
- **Real-time query log** — search, filter, blocked/allowed badges
- **Top domains & trend charts** — DNS analytics at a glance
- **DNSSEC** — root key initialization out of the box

### 📊 Monitoring & Metrics

- **Built-in TSDB** — JSONL time-series database with gzip rotation and configurable retention (default 365 days)
- **30-second metric sampling** — RX/TX bytes, handshake timestamps per peer
- **Traffic charts** — per-peer bandwidth graphs (6 h, 24 h, 3 d, 7 d)
- **Connection status** — live doughnut chart: connected vs. offline peers
- **Dashboard** — stats cards, recent activity sidebar, auto-refresh with backoff

### 🗺️ GeoIP & Location Intelligence

- **MaxMind GeoLite2** — automatic IP geolocation for peer endpoints
- **Interactive map** — Leaflet.js with heatmap layer showing peer locations
- **Country flags & ASN badges** — visual context at a glance
- **Auto-updating** — weekly GeoIP database refresh in the background

### 🔐 Let's Encrypt (ACME)

- **Built-in ACME client** — production & staging Let's Encrypt directories
- **HTTP-01 challenge** — automatic challenge serving
- **Certificate management UI** — request, list, renew, delete certificates
- **Worker-safe** — file-based domain locks prevent concurrent orders

### 👥 User Management

- **Multi-user with roles** — admin and standard user roles
- **Self-service password change** — with current-password verification
- **Login tracking** — last login timestamp and IP recorded
- **Token lifecycle** — create, refresh, revoke auth tokens; automatic cleanup

### 🎨 Web UI

- **Responsive Bootstrap 5** — optimized for desktop and mobile
- **Dark / Light / Auto theme** — system-preference detection, zero-flash
- **Six pages** — Dashboard, Peers, DNS, Settings (tabbed), Users, About
- **Auto-refresh & reconnect** — 30 s polling with exponential backoff; overlay on disconnect
- **Material Icons** — consistent iconography across the UI

---

## ⚙️ Configuration

Environment variables (via `settings.env` or Docker env):

| Variable | Default | Description |
|---|---|---|
| `WIREBUDDY_SECRET_KEY` | *(required)* | Encryption key for secrets & sessions |
| `WIREBUDDY_DATA_DIR` | `/data` | Persistent data directory |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

---

## 📡 API

Full RESTful JSON API with automatic OpenAPI documentation:

| Endpoint | Description |
|---|---|
| `GET /api/docs` | Swagger UI |
| `GET /api/redoc` | ReDoc |
| `/api/wireguard/*` | Interfaces & peers CRUD |
| `/api/dns/*` | Unbound control & query logs |
| `/api/acme/*` | Let's Encrypt certificates |
| `/api/users/*` | User management |

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

## 🏗️ Project Structure

```
wirebuddy/
├── app/
│   ├── api/           # REST API routes (wireguard, dns, acme, auth, users)
│   ├── db/            # SQLite (WAL mode) + JSONL TSDB
│   ├── dns/           # Unbound integration
│   ├── middleware/     # CSRF protection
│   ├── models/        # Pydantic request/response schemas
│   ├── templates/     # Jinja2 HTML templates
│   ├── utils/         # Config, crypto, vault, GeoIP, scheduler
│   └── static/        # CSS, JS, vendor libs, images
├── data/              # Persistent volume (DB, TSDB, GeoIP, certs)
├── docker-compose.yml
├── Dockerfile         # Multi-stage (builder → runtime)
├── requirements.txt
└── settings.env
```

---

## 📝 License

This project is licensed under the **GNU Affero General Public License v3.0** — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Made with ☕ by <a href="https://github.com/Gill-Bates">Gill-Bates</a> | © 2026
</p>
