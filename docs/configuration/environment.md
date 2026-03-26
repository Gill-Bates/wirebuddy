# Environment Variables

WireBuddy can be configured via environment variables in `settings.env` (Docker) or `.env` (local development).

## Required Variables

### WIREBUDDY_SECRET_KEY

**Required** encryption key for secrets and session management.

```bash
WIREBUDDY_SECRET_KEY=your_generated_secret_key_here
```

**Generate a secure key:**

```bash
# Using OpenSSL
openssl rand -base64 32

# Using Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

!!! danger "Security Critical"
    - **Never commit this to version control**
    - **Use a different key for each environment**
    - **Regenerating this key will invalidate all sessions and encrypted data**

## Optional Variables

### LOG_LEVEL

Logging verbosity level.

```bash
LOG_LEVEL=INFO
```

Options:

- `DEBUG` - Verbose logging (development only)
- `INFO` - Standard logging (recommended)
- `WARNING` - Warnings and errors only
- `ERROR` - Errors only
- `CRITICAL` - Critical errors only

Default: `INFO`

### PORT

Web server port.

```bash
PORT=8000
```

Default: `8000`

!!! note
    When using `network_mode: host`, the port must be available on the host.

### HOST

Web server bind address.

```bash
HOST=0.0.0.0
```

Options:

- `0.0.0.0` - Listen on all interfaces (default)
- `127.0.0.1` - Localhost only
- Specific IP - Bind to specific interface

Default: `0.0.0.0`

### WORKERS

Number of Uvicorn worker processes.

```bash
WORKERS=4
```

Default: `1` (automatic for Docker)

!!! tip
    Set to number of CPU cores for production: `WORKERS=$(nproc)`

### SERVER_MODE

Deployment mode for multi-node architecture.

```bash
SERVER_MODE=master
```

Options:

- `master` - Full application with web UI, database, and API (default)
- `node` - Lightweight WireGuard-only mode for remote nodes

Default: `master`

!!! info "Multi-Node Deployment"
    See [Multi-Node Deployment](../features/multi-node.md) for complete setup guide.

### WIREBUDDY_ENROLLMENT_TOKEN

Node enrollment token (node mode only).

```bash
WIREBUDDY_ENROLLMENT_TOKEN=eyJub2RlX2lkIjoiYWJjZGVmIiwiZXhwIjoxNzQwMDAwMDAwfQ.a1b2c3d4...
```

**Required when `SERVER_MODE=node`**. Obtain this token from the master's Nodes page.

!!! danger "Single-Use Token"
    The token is invalidated after successful enrollment. Store securely.

### WIREBUDDY_MASTER_URL

Master server API URL (node mode only).

```bash
WIREBUDDY_MASTER_URL=https://master.example.com
```

**Required when `SERVER_MODE=node`**. Must be reachable from the node server.

!!! tip "Firewall Configuration"
    Ensure the node can reach the master's sync endpoints: `/api/nodes/enroll`, `/api/nodes/{id}/heartbeat`, `/api/nodes/{id}/config`

### WIREBUDDY_SKIP_NETWORK_CHECK

Skip container network mode verification (CI/CD only).

```bash
WIREBUDDY_SKIP_NETWORK_CHECK=1
```

Default: Not set

!!! warning
    Only use for testing. WireBuddy requires host network mode for full functionality.

### DATABASE_PATH

Custom database location.

```bash
DATABASE_PATH=/custom/path/wirebuddy.db
```

Default: `data/wirebuddy.db`

### DATA_DIR

Base data directory.

```bash
DATA_DIR=/custom/data
```

Default: `data/`

### TSDB_PATH

Time-series database location.

```bash
TSDB_PATH=/custom/tsdb
```

Default: `data/tsdb/`

### GEOIP_DATA_DIR

GeoLite2 database directory.

```bash
GEOIP_DATA_DIR=/custom/geoip
```

Default: `data/geolite2/`

### DNS_LOG_PATH

Unbound DNS log file location.

```bash
DNS_LOG_PATH=/var/log/unbound/queries.log
```

Default: `data/dns/queries.log`

### CERT_DIR

ACME certificate storage directory.

```bash
CERT_DIR=/custom/certs
```

Default: `data/certs/`

## Advanced Variables

### WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS

Comma-separated list of trusted proxy CIDRs for the `/status` endpoint.

```bash
WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS=127.0.0.1/32,192.168.1.10/32
```

Default: unset

Behavior:

- Loopback proxy hops are trusted automatically
- Other proxy hops are trusted only when listed here
- Used for accepting `X-Forwarded-For` or `X-Real-IP` on `/status`

### SESSION_COOKIE_NAME

Custom session cookie name.

```bash
SESSION_COOKIE_NAME=wirebuddy_session
```

Default: `wirebuddy_session`

### SESSION_COOKIE_SECURE

Require HTTPS for session cookies.

```bash
SESSION_COOKIE_SECURE=true
```

Default: `false` (auto-detect when behind reverse proxy)

### SESSION_COOKIE_HTTPONLY

Prevent JavaScript access to session cookies.

```bash
SESSION_COOKIE_HTTPONLY=true
```

Default: `true` (recommended)

### SESSION_COOKIE_SAMESITE

SameSite cookie attribute.

```bash
SESSION_COOKIE_SAMESITE=Lax
```

Options:

- `Strict` - Strictest (may break some workflows)
- `Lax` - Balanced (recommended)
- `None` - Least strict (requires `SESSION_COOKIE_SECURE=true`)

Default: `Lax`

### RATELIMIT_ENABLED

Enable rate limiting.

```bash
RATELIMIT_ENABLED=true
```

Default: `true`

### RATELIMIT_LOGIN_ATTEMPTS

Maximum login attempts before lockout.

```bash
RATELIMIT_LOGIN_ATTEMPTS=5
```

Default: `5`

### RATELIMIT_LOGIN_WINDOW

Login rate limit window (minutes).

```bash
RATELIMIT_LOGIN_WINDOW=15
```

Default: `15`

### SWAGGER_ENABLED

Enable Swagger/OpenAPI documentation endpoint.

```bash
SWAGGER_ENABLED=false
```

Default: `true` (can disable in production)

Access at: `http://localhost:8000/docs`

### CORS_ORIGINS

Allowed CORS origins (comma-separated).

```bash
CORS_ORIGINS=https://vpn.example.com,https://admin.example.com
```

Default: Not set (CORS disabled)

### TZ

Timezone for scheduled tasks (backups run at 03:00 local time). Uses standard IANA timezone names.

```bash
TZ=America/New_York
```

See: [List of tz database time zones](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)

Default: `Etc/UTC`

## Example Configuration Files

### Production (settings.env)

```bash
# Required
WIREBUDDY_SECRET_KEY=<generated-secret-key>

# Application
LOG_LEVEL=INFO
PORT=8000
WORKERS=4

# Security
SESSION_COOKIE_SECURE=true
RATELIMIT_ENABLED=true
SWAGGER_ENABLED=false

# Optional
TZ=America/New_York
```

### Development (.env)

```bash
# Required
WIREBUDDY_SECRET_KEY=dev-secret-key-change-me

# Application
LOG_LEVEL=DEBUG
PORT=8000
WORKERS=1

# Security (relaxed for dev)
SESSION_COOKIE_SECURE=false
RATELIMIT_ENABLED=false
SWAGGER_ENABLED=true

# Optional
DATA_DIR=./dev-data
```

### Docker Compose

```yaml
services:
  wirebuddy:
    image: giiibates/wirebuddy:latest
    env_file:
      - settings.env
    environment:
      - LOG_LEVEL=INFO
      - PORT=8000
```

## Precedence

Environment variables follow this precedence (highest to lowest):

1. Docker Compose `environment` section
2. Docker Compose `env_file`
3. Shell environment
4. `.env` file
5. Application defaults

## Security Best Practices

### Secret Management

**Don't:**

- ❌ Commit secrets to Git
- ❌ Use weak secrets (`admin`, `password123`)
- ❌ Reuse secrets across environments
- ❌ Share secrets in plain text (email, Slack)

**Do:**

- ✅ Generate strong random secrets
- ✅ Use different secrets per environment
- ✅ Store secrets in secure vault (1Password, Bitwarden, Vault)
- ✅ Rotate secrets periodically
- ✅ Use `.env.example` for documentation (no real secrets)

### File Permissions

Protect environment files:

```bash
# settings.env should be readable only by owner
chmod 600 settings.env

# Verify
ls -la settings.env
# -rw------- 1 user user 123 Mar 15 10:00 settings.env
```

### Docker Secrets

For Docker Swarm, use Docker secrets:

```yaml
services:
  wirebuddy:
    secrets:
      - wirebuddy_secret_key
    environment:
      - WIREBUDDY_SECRET_KEY_FILE=/run/secrets/wirebuddy_secret_key

secrets:
  wirebuddy_secret_key:
    external: true
```

## Troubleshooting

### Changes Not Applied

**Problem:** Environment variable changes not taking effect

**Solutions:**

1. Restart container:
   ```bash
   docker compose restart wirebuddy
   ```

2. Verify variable is set:
   ```bash
   docker compose exec wirebuddy env | grep WIREBUDDY
   ```

3. Check for typos in variable names

### Invalid Secret Key

**Error:** `Failed to decrypt data`

**Cause:** `WIREBUDDY_SECRET_KEY` changed or lost

**Solutions:**

1. Restore correct secret key from backup
2. Or reinitialize database (loses encrypted data):
   ```bash
   docker compose down
   rm data/wirebuddy.db
   docker compose up -d
   ```

### Port Already in Use

**Error:** `Address already in use`

**Solutions:**

1. Change `PORT` to unused port
2. Or stop conflicting service:
   ```bash
   sudo lsof -i :8000
   sudo kill <PID>
   ```

## Next Steps

- [WireGuard Configuration](wireguard.md)
- [DNS Configuration](dns.md)
- [Security Configuration](security.md)
- [Best Practices](../security/best-practices.md)
