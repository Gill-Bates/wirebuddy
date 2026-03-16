---
hide:
  - navigation
---

# WireBuddy

<p align="center">
  <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/wirebuddy_black.svg" width="400" alt="WireBuddy Logo" class="wb-logo-light">
  <img src="https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/wirebuddy_white.svg" width="400" alt="WireBuddy Logo" class="wb-logo-dark">
</p>

<p align="center">
  <strong>Modern WireGuard VPN Management with Integrated DNS Ad-Blocking</strong>
</p>

<p align="center">
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/v/giiibates/wirebuddy?label=Docker%20Hub&logo=docker&logoColor=white" alt="Docker Hub"></a>
  <a href="https://hub.docker.com/r/giiibates/wirebuddy"><img src="https://img.shields.io/docker/pulls/giiibates/wirebuddy?logo=docker&logoColor=white" alt="Docker Pulls"></a>
  <a href="https://github.com/Gill-Bates/wirebuddy"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="License"></a>
</p>

---

## What is WireBuddy?

WireBuddy is a powerful, user-friendly web interface for managing WireGuard VPN servers with built-in DNS ad-blocking capabilities. It combines enterprise-grade security features with an intuitive interface, making VPN management accessible to both beginners and advanced users.

## Key Features

<div class="grid cards" markdown>

-   :material-shield-lock:{ .lg .middle } **Secure VPN Management**

    ---

    Multi-interface WireGuard management with automatic keypair generation, routing presets, and QR codes for easy mobile setup.

    [:octicons-arrow-right-24: WireGuard Features](features/wireguard.md)

-   :material-dns:{ .lg .middle } **DNS Ad-Blocking**

    ---

    Integrated Unbound resolver with customizable blocklists, DNS-over-TLS, real-time query logging, and per-client custom rules.

    [:octicons-arrow-right-24: DNS Features](features/dns.md)

-   :material-chart-line:{ .lg .middle } **Analytics & Monitoring**

    ---

    Built-in time-series database with per-peer traffic charts, GeoIP mapping, and traffic analysis by country & ASN.

    [:octicons-arrow-right-24: Monitoring](features/monitoring.md)

-   :material-account-lock:{ .lg .middle } **Advanced Authentication**

    ---

    Multi-user support with Passkeys (WebAuthn), TOTP, and granular role-based access control.

    [:octicons-arrow-right-24: User Management](features/users.md)

-   :material-certificate:{ .lg .middle } **Let's Encrypt Integration**

    ---

    Built-in ACME client with HTTP-01 challenge for automatic SSL certificate management.

    [:octicons-arrow-right-24: ACME](features/acme.md)

-   :material-palette:{ .lg .middle } **Modern Web UI**

    ---

    Responsive Bootstrap 5 interface with dark/light/auto theme and Material Design icons.

    [:octicons-arrow-right-24: Getting Started](getting-started/quick-start.md)

</div>

## Quick Start

Get WireBuddy up and running in minutes:

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
cp .env-example settings.env
# Edit settings.env - set WIREBUDDY_SECRET_KEY!
docker compose up -d
```

!!! success "Default Access"
    Navigate to `http://localhost:8000` and login with:
    
    - **Username:** `admin`
    - **Password:** `admin`
    
    !!! warning
        Change the default password immediately after first login!

[:material-rocket-launch: Full Installation Guide](getting-started/installation.md){ .md-button .md-button--primary }
[:material-book-open-page-variant: Quick Start](getting-started/quick-start.md){ .md-button }

## Screenshots

=== "Dashboard"
    ![Dashboard](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen1.png)
    
=== "Peer Management"
    ![Peers](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen2.png)
    
=== "DNS Ad-Blocker"
    ![DNS](https://raw.githubusercontent.com/Gill-Bates/wirebuddy/main/.github/img/screen3.png)

## Why WireBuddy?

| Feature | WireBuddy | Traditional Solutions |
|---------|-----------|----------------------|
| Web Interface | ✅ Modern & Responsive | ⚠️ CLI or Basic Web UI |
| DNS Ad-Blocking | ✅ Built-in Unbound | ❌ Requires Separate Setup |
| Traffic Analytics | ✅ Per-peer with GeoIP | ⚠️ Limited or None |
| Multi-User Auth | ✅ Passkeys + TOTP | ⚠️ Single Admin Only |
| Let's Encrypt | ✅ Integrated | ❌ Manual Configuration |
| Docker Support | ✅ Official Images | ⚠️ Community Maintained |

## Security First

WireBuddy implements defense-in-depth security:

- **Password Security:** PBKDF2-SHA256 with 600,000 iterations
- **Passkeys Support:** WebAuthn (FIDO2) for passwordless authentication
- **Secrets Encryption:** Fernet encryption with per-row salt
- **CSRF Protection:** Double-submit cookie with Origin validation
- **Rate Limiting:** Progressive IP lockout with backoff
- **Input Validation:** Strict regex and Pydantic validation
- **Container Hardening:** Minimal capabilities and no-new-privileges

[:material-shield-check: Security Overview](security/overview.md){ .md-button }

## Community & Support

<div class="grid" markdown>

[:fontawesome-brands-github: GitHub Repository](https://github.com/Gill-Bates/wirebuddy){ .md-button }
[:fontawesome-brands-docker: Docker Hub](https://hub.docker.com/r/giiibates/wirebuddy){ .md-button }
[:material-bug: Report Issues](https://github.com/Gill-Bates/wirebuddy/issues){ .md-button }

</div>

## License

WireBuddy is licensed under the [GNU Affero General Public License v3.0](license.md).

---

<p align="center">
  Made with ☕ by <a href="https://github.com/Gill-Bates">Gill-Bates</a>
</p>
