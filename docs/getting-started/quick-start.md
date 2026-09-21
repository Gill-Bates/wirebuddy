---
title: Quick Start
---

# Quick Start Guide

Get WireBuddy running in under 5 minutes with Docker.

## Prerequisites

Before you begin, ensure you have:

- Docker Engine 20.10+ and Docker Compose
- Linux host (amd64 or arm64)
- Root or sudo access for sysctl configuration

!!! tip "Windows & macOS Users"
    WireBuddy requires `network_mode: host` which is only fully supported on Linux. For Windows/macOS, consider running it in a Linux VM.

## Step 1: Clone the Repository

```bash
git clone https://github.com/Gill-Bates/wirebuddy.git
cd wirebuddy
```

## Step 2: Configure Settings

Copy the example environment file and edit it:

```bash
cp .env-example .env
nano .env  # or use your preferred editor
```

**Required:** Set a secure `WIREBUDDY_SECRET_KEY`:

```bash
# Generate a secure key (Linux/macOS)
openssl rand -base64 32

# Or use Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

??? example "Example .env"
    ```bash
    # Required: Encryption key for secrets & sessions
    WIREBUDDY_SECRET_KEY=your-generated-secret-key-here
    
    # Optional: Logging level
    LOG_LEVEL=INFO
    
    # Optional: Skip network mode check (CI/CD only)
    # WIREBUDDY_SKIP_NETWORK_CHECK=1
    ```

## Step 3: Enable IP Forwarding

WireGuard requires IP forwarding on the host:

```bash
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1

# Make persistent across reboots
cat <<EOF | sudo tee /etc/sysctl.d/99-wireguard.conf
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
EOF
```

## Step 4: Enable Conntrack Accounting (Optional but Recommended)

For traffic analysis by country and ASN, enable conntrack byte accounting:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1

# Make persistent
echo "net.netfilter.nf_conntrack_acct = 1" | sudo tee -a /etc/sysctl.d/99-wireguard.conf
```

Verify it's enabled:

```bash
cat /proc/sys/net/netfilter/nf_conntrack_acct
# Should output: 1
```

!!! warning "Without Conntrack Accounting"
    Country and ASN traffic charts will show no data. WireBuddy will log a warning but continue to function.

## Step 5: Start WireBuddy

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

Check the logs:

```bash
docker compose --env-file .env -f docker/docker-compose.yml logs -f wirebuddy
```

## Step 6: Access the Web Interface

Open your browser and navigate to:

```
http://localhost:8000
```

Or access from your network using the server's IP address:

```
http://YOUR_SERVER_IP:8000
```

!!! success "Bootstrap Credentials"
    - **Username:** `admin`
    - **Password:** check the server log — run `docker logs wirebuddy` and look for the generated temporary password

WireBuddy will redirect you to a password change screen on first login. Set a secure password to continue.

## Step 7: Secure with Reverse Proxy (Recommended)

For production use, place WireBuddy behind a reverse proxy with HTTPS. Ready-to-use
Caddy, Nginx and Traefik configurations, including the unbuffered event-stream
routes multi-node deployments need, are in the
[Installation Guide](installation.md#reverse-proxy).

## Next Steps

Now that WireBuddy is running:

1. **[First Steps](first-steps.md)** - Configure your first WireGuard interface
2. **[WireGuard Management](../features/wireguard.md)** - Learn about peer management
3. **[DNS Ad-Blocking](../features/dns.md)** - Set up DNS filtering
4. **[User Management](../features/users.md)** - Add additional users and enable MFA

## Troubleshooting

!!! bug "Common Issues"
    
    **Container won't start:**
    ```bash
    # Check logs
    docker compose --env-file .env -f docker/docker-compose.yml logs wirebuddy
    
    # Verify network mode
    docker inspect wirebuddy | grep NetworkMode
    # Should show: "host"
    ```
    
    **Can't access web interface:**
    - Verify port 8000 is not blocked by firewall
    - Check if another service is using port 8000:
      ```bash
      sudo netstat -tulpn | grep :8000
      ```
    
    **Traffic charts show no data:**
    - Verify conntrack accounting is enabled (see Step 4)
    - Check WireBuddy logs for warnings

For more help, see the [Troubleshooting](../troubleshooting.md) page or [open an issue](https://github.com/Gill-Bates/wirebuddy/issues).

## Updating WireBuddy

To update to the latest version:

```bash
cd wirebuddy
docker compose --env-file .env -f docker/docker-compose.yml pull
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

!!! info "Data Persistence"
    Your configuration and data are stored in `docker/data/` and persist across updates.
