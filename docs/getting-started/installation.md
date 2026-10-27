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

- Python 3.13+
- pip and venv
- System dependencies:
  - WireGuard tools (`wg`, `wg-quick`)
  - Unbound DNS resolver
  - conntrack-tools (optional, for traffic analytics)

### 1. Install System Dependencies

=== "Ubuntu/Debian"
    ```bash
    sudo apt update
    sudo apt install -y \
      python3.13 python3.13-venv python3-pip \
      wireguard-tools \
      unbound \
      conntrack
    ```

=== "Fedora/RHEL/CentOS"
    ```bash
    sudo dnf install -y \
      python3.13 python3-pip \
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
python3.13 -m venv .venv
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
python run.py
```

Or use uvicorn directly:

```bash
uvicorn app:create_app --factory --host 0.0.0.0 --port 8000
```

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
    (proxy_common) {
        header_up X-Forwarded-Proto https
        header_up X-Forwarded-Port 443

        transport http {
            keepalive 30s
        }
    }

    vpn.example.com {
        # Live event streams used by nodes and the admin UI: disable buffering so
        # speedtest progress and node events reach users in real time.
        @sse path_regexp sse ^(?:/api/nodes/events|/api/wireguard/speedtest/run/stream/[^/]+|/api/nodes/[^/]+/speedtest/stream)$
        reverse_proxy @sse localhost:8000 {
            import proxy_common
            flush_interval -1
        }

        # Default reverse proxy
        reverse_proxy localhost:8000 {
            import proxy_common
        }

        # Compression
        encode gzip

        # Cache static assets (1 year)
        @static path /static/*
        header @static Cache-Control "public, max-age=31536000, immutable"

        # Security headers
        header {
            Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
            X-Content-Type-Options nosniff
            X-Frame-Options SAMEORIGIN
            Referrer-Policy strict-origin-when-cross-origin
            -Server
            -X-Powered-By
        }

        # Request body limit
        request_body {
            max_size 100MB
        }

        # Logging
        log {
            output file /var/log/caddy/access.log {
                roll_size 10mb
            }
        }
    }
    ```
    
    !!! tip "SSE Support for Node Events"
        The `@sse` matcher with `flush_interval -1` ensures real-time server-sent events work correctly for multi-node deployments.

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
        
        # Request body limit
        client_max_body_size 100M;
        
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
      
      # Request body limit (100MB for backups)
      - "traefik.http.middlewares.wirebuddy-body.buffering.maxRequestBodyBytes=104857600"
      
      # Apply middlewares
      - "traefik.http.routers.wirebuddy.middlewares=wirebuddy-headers,wirebuddy-body"
    ```
    
    !!! tip "SSE Support"
        Traefik automatically handles SSE correctly by default. No special configuration needed for `/api/nodes/events`.

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
