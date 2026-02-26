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
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Platform-linux%2Famd64%20|%20linux%2Farm64-lightgrey?logo=linux&logoColor=white" alt="Platform"></a>
</p>

A complete self-hosted VPN solution with web-based management, integrated Unbound DNS resolver, ad-blocking, real-time traffic analytics, and GeoIP visualization.

## Key Features

- **Multi-interface WireGuard management** with automatic peer configuration
- **Integrated Unbound DNS** with blocklist support (StevenBlack, HaGeZi Pro) and DNS-over-TLS upstream
- **Client-scoped DNS filter rules** — define custom allow/block rules per VPN client
- **Real-time traffic monitoring** and DNS query analytics with built-in time-series database
- **Interactive GeoIP heatmap** with MaxMind GeoLite2 integration
- **One-tap mobile setup** via QR codes
- **Multi-user authentication** with role-based access control (Admin/User) and MFA (TOTP)
- **Let's Encrypt ACME support** for automatic HTTPS certificates
- Built with **Python 3.13**, **FastAPI**, and **Bootstrap 5**

<br>
<p>Perfect for privacy-focused users, homelab enthusiasts, and small teams who want a powerful VPN solution with enterprise-grade features in a Docker container.</p>

---

**Default credentials:** `admin` / `admin` *(change immediately!)*