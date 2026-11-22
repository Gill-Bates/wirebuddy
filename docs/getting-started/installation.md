---
title: Installation
---

# Installation Guide

Installation instructions for WireBuddy with Docker Compose, Docker Run or a local development setup.

## Installation Methods

WireBuddy can be installed in several ways:

| Method | Difficulty | Best For |
|--------|-----------|----------|
| [Docker Compose](#docker-compose-recommended) | ⭐ Easy | Production, most users |
| [Docker Run](docker.md#docker-run) | ⭐⭐ Moderate | Custom setups |
| [Local Development](#local-development) | ⭐⭐⭐ Advanced | Development, testing |

---

## Docker Compose (Recommended)

The easiest and most reliable way to run WireBuddy.

### 1. Install Docker

=== "Ubuntu/Debian"
    ```bash
    # Install Docker
    curl -fsSL https://get.docker.com | sh
    
    # Add your user to docker group
    sudo usermod -aG docker $USER
    
    # Enable Docker service
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Log out and back in for group changes to take effect
    ```

=== "Fedora/RHEL/CentOS"
    ```bash
    # Install Docker
    sudo dnf install docker docker-compose
    
    # Start and enable Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add your user to docker group
    sudo usermod -aG docker $USER
    ```

=== "Arch Linux"
    ```bash
    # Install Docker
    sudo pacman -S docker docker-compose
    
    # Start and enable Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Add your user to docker group
    sudo usermod -aG docker $USER
    ```

### 2. Install and start WireBuddy

Follow the [Quick Start](quick-start.md) for the sysctl settings (IP
forwarding, conntrack accounting), the `.env` file, the first start and the
bootstrap credentials. The [Docker Setup](docker.md) guide covers the Compose
file, its capabilities and security options, persistent data, health checks and
`docker run`.

!!! warning "Network Mode Host"
    WireBuddy requires `network_mode: host` to manage WireGuard interfaces and access conntrack statistics. This is a Linux-specific feature.

---

## Local Development

For development or non-Docker deployments.

### Prerequisites

- Python 3.14+
- pip and venv
- System dependencies:
  - WireGuard tools (`wg`, `wg-quick`)
  - Unbound DNS resolver
  - conntrack-tools (optional, for traffic analytics)

### 1. Install System Dependencies

=== "Ubuntu 26.04 / Debian testing"
    `python3.14` is packaged on Ubuntu 26.04 and Debian testing/unstable. Older
    releases (for example Debian 13 or Ubuntu 24.04) do not ship it: install
    Python 3.14 with [uv](https://docs.astral.sh/uv/getting-started/installation/)
    (`uv python install 3.14`, which provides `python3.14` in `~/.local/bin`) or use
    the Docker image instead. Skip `python3.14` and `python3.14-venv` in the package
    list below and create the virtual environment with `uv venv --python 3.14 .venv`.

    ```bash
    sudo apt update
    sudo apt install -y \
      python3.14 python3.14-venv python3-pip \
      wireguard-tools \
      unbound \
      conntrack
    ```

=== "Fedora/RHEL/CentOS"
    ```bash
    sudo dnf install -y \
      python3.14 python3-pip \
      wireguard-tools \
      unbound \
      conntrack-tools
    ```

=== "Arch Linux"
    ```bash
    sudo pacman -S \
      python python-pip \
      wireguard-tools \
      unbound \
      conntrack-tools
    ```

### 2. Clone Repository

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
```

### 3. Create Virtual Environment

```bash
python3.14 -m venv .venv
source .venv/bin/activate
```

### 4. Install Python Dependencies

```bash
pip install .
```

### 5. Configure Environment

```bash
cp .env-example .env
```

Edit `.env` and set your `WIREBUDDY_SECRET_KEY`. To enable hot reload, also set:

```bash
WIREBUDDY_DEV_RELOAD=true
```

### 6. System Configuration

Apply the sysctl settings described in the [Quick Start](quick-start.md#step-3-enable-ip-forwarding):

```bash
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

### 7. Run WireBuddy

```bash
python -m app.server   # a local start does not read .env: load it first with `set -a; source .env; set +a`
```

Or use uvicorn directly:

```bash
uvicorn app:create_app --factory --host 0.0.0.0 --port 8000
```

Started this way, the node mTLS fingerprint header is always ignored. Use
`python -m app.server` if a proxy listed in `WIREBUDDY_MTLS_PROXIES` terminates
mTLS.

For production, keep a single worker:

```bash
uvicorn app:create_app --factory \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 1 \
  --log-level info
```

Do not run the web UI with multiple Uvicorn workers. Startup tasks and
authentication state are process-local.

---

## Post-Installation

After installation, proceed with:

1. **[First Steps](first-steps.md)** - Initial configuration
2. **[Security Best Practices](../security/best-practices.md)** - Harden your installation
3. **[Configuration](../configuration/environment.md)** - Advanced settings

## Updating WireBuddy

See [Docker Setup: Updating](docker.md#updating).

## Reverse Proxy

For production use, place WireBuddy behind a reverse proxy with HTTPS.

=== "Caddy"
    ```caddyfile
    # Caddyfile (included in repository)
    vpn.example.com {
        reverse_proxy localhost:8000

        encode gzip

        header {
            -Server
            -X-Powered-By
        }

        # App restore limit is 1 GiB; the margin covers multipart overhead.
        request_body {
            max_size 1100MB
        }

        log {
            output file /var/log/caddy/access.log {
                roll_size 10mb
            }
        }
    }
    ```

    !!! tip "Server-sent events"
        Caddy streams `text/event-stream` responses without extra settings, so node events and speedtest progress need no special proxy configuration.

=== "Nginx"
    ```nginx
    server {
        listen 443 ssl http2;
        server_name vpn.example.com;
        
        # SSL Configuration
        ssl_certificate /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        # Security Headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options SAMEORIGIN always;
        add_header Referrer-Policy strict-origin-when-cross-origin always;
        
        # App restore limit is 1 GiB; the margin covers multipart overhead.
        client_max_body_size 1100M;
        
        # SSE endpoint: disable buffering for real-time events
        location /api/nodes/events {
            proxy_pass http://localhost:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Connection '';
            proxy_buffering off;
            proxy_cache off;
            chunked_transfer_encoding off;
        }
        
        # Static assets: aggressive caching
        location /static/ {
            proxy_pass http://localhost:8000;
            proxy_set_header Host $host;
            add_header Cache-Control "public, max-age=31536000, immutable";
        }
        
        # Default location
        location / {
            proxy_pass http://localhost:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
        }
    }
    ```
    
    !!! warning "SSE Support Required"
        The `/api/nodes/events` location with `proxy_buffering off` is essential for real-time node event streaming in multi-node deployments.

=== "Traefik"
    ```yaml
    # docker-compose.yml labels
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wirebuddy.rule=Host(`vpn.example.com`)"
      - "traefik.http.routers.wirebuddy.entrypoints=websecure"
      - "traefik.http.routers.wirebuddy.tls.certresolver=letsencrypt"
      
      # Security Headers
      - "traefik.http.middlewares.wirebuddy-headers.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.wirebuddy-headers.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.wirebuddy-headers.headers.stsPreload=true"
      - "traefik.http.middlewares.wirebuddy-headers.headers.contentTypeNosniff=true"
      - "traefik.http.middlewares.wirebuddy-headers.headers.frameDeny=true"
      - "traefik.http.middlewares.wirebuddy-headers.headers.customResponseHeaders.Referrer-Policy=strict-origin-when-cross-origin"
      
      - "traefik.http.routers.wirebuddy.middlewares=wirebuddy-headers"
      
      # Request body limit (1100 MiB: 1 GiB backup restore plus multipart overhead),
      # applied only to the restore upload on its own router
      - "traefik.http.middlewares.wirebuddy-body.buffering.maxRequestBodyBytes=1153433600"
      - "traefik.http.routers.wirebuddy-restore.rule=Host(`vpn.example.com`) && Path(`/api/backup/restore`)"
      - "traefik.http.routers.wirebuddy-restore.entrypoints=websecure"
      - "traefik.http.routers.wirebuddy-restore.tls.certresolver=letsencrypt"
      - "traefik.http.routers.wirebuddy-restore.middlewares=wirebuddy-headers,wirebuddy-body"
    ```
    
    !!! warning "Server-sent events"
        Traefik streams `text/event-stream` responses without extra settings, but the buffering middleware also buffers responses. Keep it off the routes that serve node events (`/api/nodes/events`) and speed test progress, as above; the longer restore rule takes priority over the main router.

## Firewall Configuration

If you're running a firewall, you need to allow:

- **Port 8000/tcp** - Web interface (or your custom port)
- **Port 51820/udp** - WireGuard (default, adjust per interface)
- **Port 53/udp** - DNS (if using WireBuddy as DNS server)

=== "UFW"
    ```bash
    sudo ufw allow 8000/tcp
    sudo ufw allow 51820/udp
    sudo ufw allow 53/udp
    ```

=== "firewalld"
    ```bash
    sudo firewall-cmd --permanent --add-port=8000/tcp
    sudo firewall-cmd --permanent --add-port=51820/udp
    sudo firewall-cmd --permanent --add-port=53/udp
    sudo firewall-cmd --reload
    ```

=== "iptables"
    ```bash
    sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT
    sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
    ```

## Next Steps

- [First Steps Guide](first-steps.md)
- [WireGuard Configuration](../configuration/wireguard.md)
- [DNS Configuration](../configuration/dns.md)
- [Security Configuration](../configuration/security.md)
