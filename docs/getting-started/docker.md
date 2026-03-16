---
title: Docker Setup
---

# Docker Setup Guide

Detailed guide for running WireBuddy with Docker.

## Docker Compose Setup

### Basic Configuration

The included `docker-compose.yml` provides a basic setup:

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    container_name: wirebuddy
    restart: unless-stopped
    network_mode: host
    cap_add:
      - NET_ADMIN
    env_file:
      - settings.env
    volumes:
      - ./data:/app/data
    security_opt:
      - no-new-privileges:true
```

### Environment Variables

Create `settings.env`:

```bash
# Required: Secret key for encryption
WIREBUDDY_SECRET_KEY=your_generated_key_here

# Optional: Logging level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL=INFO

# Optional: Skip network mode check (for CI/CD only)
# WIREBUDDY_SKIP_NETWORK_CHECK=1
```

## Network Mode: Host

WireBuddy requires `network_mode: host` for several reasons:

1. **WireGuard Interface Management:** Direct access to host network stack
2. **Conntrack Statistics:** Access to `/proc/net/nf_conntrack` for traffic analytics
3. **Port Binding:** WireGuard peers connect directly to host interface

!!! warning "Linux Only"
    `network_mode: host` is fully supported only on Linux. For Windows/macOS, run WireBuddy in a Linux VM.

### Alternative: macvlan Network

For advanced users who need isolated networking:

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    networks:
      - macvlan_net
    cap_add:
      - NET_ADMIN
      - NET_RAW
    # ... other config

networks:
  macvlan_net:
    driver: macvlan
    driver_opts:
      parent: eth0
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
```

!!! caution
    macvlan requires manual configuration and may not support all features.

## Custom Port

To change the web UI port (default: 8000):

### Using Host Network

Edit `settings.env` and add:

```bash
PORT=8080
```

Or pass directly in docker-compose.yml:

```yaml
environment:
  - PORT=8080
```

### Using Bridge Network (Not Recommended)

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    network_mode: bridge
    ports:
      - "8080:8000"
    # ... other config
```

!!! warning
    Bridge mode limits functionality. Use only if you understand the implications.

## Volume Mounts

### Data Directory

WireBuddy stores all persistent data in `/app/data`:

```yaml
volumes:
  - ./data:/app/data
```

Contents:

- `wirebuddy.db` - SQLite database (configuration, users, peers)
- `certs/` - ACME certificates
- `dns/` - DNS configuration and logs
- `tsdb/` - Time-series database (metrics)
- `geolite2/` - GeoIP databases

### Read-Only Root Filesystem (Optional)

For enhanced security:

```yaml
services:
  wirebuddy:
    read_only: true
    tmpfs:
      - /tmp
      - /run
    volumes:
      - ./data:/app/data  # Must be writable
```

## Docker CLI

### Basic Run Command

```bash
docker run -d \
  --name wirebuddy \
  --network host \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  -e WIREBUDDY_SECRET_KEY="your_secret_key_here" \
  -v $(pwd)/data:/app/data \
  --restart unless-stopped \
  giiibates/wirebuddy:latest
```

### With Custom Configuration

```bash
docker run -d \
  --name wirebuddy \
  --network host \
  --cap-add NET_ADMIN \
  --security-opt no-new-privileges:true \
  --env-file settings.env \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/custom-config.yaml:/app/config.yaml:ro \
  --restart unless-stopped \
  giiibates/wirebuddy:latest
```

## Managing the Container

### Start/Stop

```bash
# Using Docker Compose
docker compose start
docker compose stop
docker compose restart

# Using Docker CLI
docker start wirebuddy
docker stop wirebuddy
docker restart wirebuddy
```

### View Logs

```bash
# Follow logs
docker compose logs -f wirebuddy

# Last 100 lines
docker logs --tail 100 wirebuddy

# Since specific time
docker logs --since 30m wirebuddy
```

### Access Container Shell

```bash
# For debugging
docker compose exec wirebuddy bash

# Or with Docker CLI
docker exec -it wirebuddy bash
```

### Update Container

```bash
# Pull latest image
docker compose pull

# Restart with new image
docker compose up -d

# Or with Docker CLI
docker pull giiibates/wirebuddy:latest
docker stop wirebuddy
docker rm wirebuddy
# Then run with same command as before
```

## Docker Image Tags

WireBuddy images are available with multiple tags:

| Tag | Description | Use Case |
|-----|-------------|----------|
| `latest` | Latest stable release | Production |
| `1.3` | Major.minor version | Pin to specific version |
| `1.3.2` | Full version tag | Pin to exact release |
| `dev` | Development branch | Testing only |

Example:

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:1.3.2  # Pin to specific version
```

## Health Checks

Add a health check to Docker Compose:

```yaml
services:
  wirebuddy:
    # ... other config
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

## Resource Limits

Limit container resources:

```yaml
services:
  wirebuddy:
    # ... other config
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 256M
```

## Multi-Stage Setup

For running multiple WireBuddy instances (e.g., dev/staging/prod):

```bash
# Directory structure
wirebuddy/
├── docker-compose.yml
├── dev/
│   ├── settings.env
│   └── data/
├── staging/
│   ├── settings.env
│   └── data/
└── prod/
    ├── settings.env
    └── data/
```

```yaml
# docker-compose.yml
services:
  wirebuddy-dev:
    image: giiibates/wirebuddy:dev
    env_file: dev/settings.env
    volumes:
      - ./dev/data:/app/data
    environment:
      - PORT=8001

  wirebuddy-staging:
    image: giiibates/wirebuddy:latest
    env_file: staging/settings.env
    volumes:
      - ./staging/data:/app/data
    environment:
      - PORT=8002

  wirebuddy-prod:
    image: giiibates/wirebuddy:1.3.2
    env_file: prod/settings.env
    volumes:
      - ./prod/data:/app/data
    environment:
      - PORT=8000
```

## Backup and Restore

### Backup Data

```bash
# Stop container
docker compose stop wirebuddy

# Create backup
tar czf wirebuddy-backup-$(date +%Y%m%d).tar.gz data/

# Or using Docker
docker run --rm \
  -v $(pwd)/data:/data \
  -v $(pwd)/backups:/backups \
  alpine tar czf /backups/backup-$(date +%Y%m%d).tar.gz /data

# Restart container
docker compose start wirebuddy
```

### Restore Data

```bash
# Stop container
docker compose stop wirebuddy

# Restore backup
tar xzf wirebuddy-backup-YYYYMMDD.tar.gz

# Restart container
docker compose start wirebuddy
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker compose logs wirebuddy

# Verify network mode
docker inspect wirebuddy | grep NetworkMode

# Check permissions
ls -la data/
```

### Permission Issues

```bash
# Fix data directory permissions
chown -R 1000:1000 data/

# Or run as root (not recommended)
docker compose run --user root wirebuddy bash
```

### Network Issues

```bash
# Verify host networking
docker run --rm --network host alpine ip addr

# Check WireGuard interface
docker compose exec wirebuddy wg show

# Verify conntrack
cat /proc/net/nf_conntrack | head
```

## Security Hardening

### AppArmor Profile

Create custom AppArmor profile:

```yaml
services:
  wirebuddy:
    security_opt:
      - apparmor=wirebuddy-profile
```

### Seccomp Profile

Use custom seccomp profile:

```yaml
services:
  wirebuddy:
    security_opt:
      - seccomp=wirebuddy-seccomp.json
```

### Drop Dangerous Capabilities

```yaml
services:
  wirebuddy:
    cap_drop:
      - ALL
    cap_add:
      - NET_ADMIN  # Only add required capabilities
```

## Next Steps

- [First Steps Guide](first-steps.md)
- [Configuration Options](../configuration/environment.md)
- [Security Best Practices](../security/best-practices.md)
