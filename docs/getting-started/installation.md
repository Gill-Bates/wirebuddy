---
title: Installation
---

# Installation Guide

Comprehensive installation instructions for WireBuddy on various platforms.

## Installation Methods

WireBuddy can be installed in several ways:

| Method | Difficulty | Best For |
|--------|-----------|----------|
| [Docker Compose](#docker-compose-recommended) | ⭐ Easy | Production, most users |
| [Docker Run](#docker-run) | ⭐⭐ Moderate | Custom setups |
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

### 2. System Configuration

Enable IP forwarding (required for WireGuard):

```bash
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

Make it persistent:

```bash
cat <<EOF | sudo tee /etc/sysctl.d/99-wireguard.conf
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
EOF
```

Enable conntrack accounting for traffic analytics:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
echo "net.netfilter.nf_conntrack_acct = 1" | sudo tee -a /etc/sysctl.d/99-wireguard.conf
```

### 3. Download WireBuddy

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
```

### 4. Configure Environment

```bash
cp .env-example settings.env
```

Generate a secure secret key:

```bash
openssl rand -base64 32
```

Edit `settings.env` and set:

```bash
WIREBUDDY_SECRET_KEY=your_generated_key_here
LOG_LEVEL=INFO
```

### 5. Review Docker Compose Configuration

The included `docker-compose.yml`:

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    container_name: wirebuddy
    restart: unless-stopped
    network_mode: host  # Required for WireGuard
    cap_add:
      - NET_ADMIN       # Required for network configuration
    env_file:
      - settings.env
    volumes:
      - ./data:/app/data
    security_opt:
      - no-new-privileges:true
```

!!! warning "Network Mode Host"
    WireBuddy requires `network_mode: host` to manage WireGuard interfaces and access conntrack statistics. This is a Linux-specific feature.

### 6. Start WireBuddy

```bash
docker compose up -d
```

View logs:

```bash
docker compose logs -f wirebuddy
```

### 7. Access Web Interface

Open your browser to:

```
http://localhost:8000
```

Default credentials:
- Username: `admin`
- Password: `admin`

!!! danger "Change Default Password"
    Immediately change the default password after first login via **Settings → Users**!

---

## Docker Run

For manual Docker container management:

```bash
docker run -d \
  --name wirebuddy \
  --network host \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  -e WIREBUDDY_SECRET_KEY="your_secret_key_here" \
  -e LOG_LEVEL=INFO \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  giiibates/wirebuddy:latest
```

---

## Local Development

For development or non-Docker deployments.

### Prerequisites

- Python 3.13+ (recommended) or 3.11+
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
pip install -r requirements.txt
```

### 5. Configure Environment

```bash
cp .env-example .env
```

Edit `.env` and set your `WIREBUDDY_SECRET_KEY`:

```bash
export WIREBUDDY_SECRET_KEY=$(openssl rand -base64 32)
```

### 6. System Configuration

Apply the same sysctl settings as in Docker installation:

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
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

For production with multiple workers:

```bash
uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level info
```

---

## Post-Installation

After installation, proceed with:

1. **[First Steps](first-steps.md)** - Initial configuration
2. **[Security Best Practices](../security/best-practices.md)** - Harden your installation
3. **[Configuration](../configuration/environment.md)** - Advanced settings

## Updating WireBuddy

To update to the latest version:

```bash
cd wirebuddy
docker compose pull
docker compose up -d
```

!!! info "Data Persistence"
    Your configuration and data are stored in the `data/` directory and persist across updates.

## Reverse Proxy

For production use, place WireBuddy behind a reverse proxy with HTTPS.

=== "Caddy"
    ```caddyfile
    # Caddyfile (included in repository)
    wirebuddy.example.com {
        reverse_proxy localhost:8000
    }
    ```

=== "Nginx"
    ```nginx
    server {
        listen 443 ssl http2;
        server_name wirebuddy.example.com;
        
        ssl_certificate /path/to/cert.pem;
        ssl_certificate_key /path/to/key.pem;
        
        location / {
            proxy_pass http://localhost:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    ```

=== "Traefik"
    ```yaml
    # docker-compose.yml labels
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wirebuddy.rule=Host(`wirebuddy.example.com`)"
      - "traefik.http.routers.wirebuddy.entrypoints=websecure"
      - "traefik.http.routers.wirebuddy.tls.certresolver=letsencrypt"
    ```

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
