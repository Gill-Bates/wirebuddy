# Environment Variables

WireBuddy reads configuration from process environment variables. Local starts
through `python run.py` also load `.env`; the configuration loader retains
`settings.env` as a lower-precedence compatibility source. Docker Compose uses
the root `.env` file explicitly in the documented commands.

## Quick Configuration

```bash
cp .env-example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Store the generated value in `.env`:

```bash
WIREBUDDY_SECRET_KEY=<generated-value>
LOG_LEVEL=INFO
TZ=Etc/UTC
```

Start the supplied Docker deployment with:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d
```

## Core Application

### `WIREBUDDY_SECRET_KEY`

Required in master mode. It encrypts WireGuard private keys, preshared keys,
OTP secrets, and other sensitive values and must contain at least 32 UTF-8
bytes.

```bash
WIREBUDDY_SECRET_KEY=<generated-value>
```

Generate it with either:

```bash
openssl rand -base64 32
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

!!! danger
    Never commit, rotate casually, or lose this key. Existing encrypted data
    cannot be recovered with a different key.

The key is not required in node mode because enrolled nodes authenticate with
their node credentials.

### `SERVER_MODE`

Selects the process role:

- `master`: web UI, API, database, DNS, scheduling, and node management
- `node`: remote WireGuard node daemon without the web UI

Default: `master`.

### `LOG_LEVEL`

Accepted values: `CRITICAL`, `ERROR`, `WARNING`, `INFO`, and `DEBUG`.

Default: `INFO`. Invalid values fall back to `INFO`.

### `TZ`

IANA time-zone name used by scheduled tasks and UI formatting.

```bash
TZ=Europe/Berlin
```

Docker default: `Etc/UTC`.

### `WIREBUDDY_DATA_DIR`

Base directory for persistent data. The database, TSDB, DNS files,
certificates, and GeoIP databases live below it.

- Local default: `<project>/data`
- Supplied Docker Compose value: `/app/data`

## Web Server

### `WIREBUDDY_HOST`

Docker-entrypoint override for the web bind address.

Without this override, the entrypoint reads **Only listen on Localhost** from
the database and otherwise listens on `0.0.0.0` for a fresh installation.

```bash
WIREBUDDY_HOST=127.0.0.1
```

### `WIREBUDDY_PORT`

Docker-entrypoint override for the GUI port. Valid range: `1`–`65535`.

Without this override, the entrypoint uses the database setting **HTTP Port
(GUI)**. Fresh-installation default: `8000`.

```bash
WIREBUDDY_PORT=8080
```

`HOST` and `PORT` are not WireBuddy configuration variables.

### `UVICORN_WORKERS`

The web application supports one worker only. The Docker entrypoint forces any
other value back to `1` because authentication and runtime coordination contain
process-local state.

Default: `1`.

### `UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT`

Docker Uvicorn graceful-shutdown timeout in seconds. Accepted range: `1`–`300`.

Default: `8`.

### `WIREBUDDY_DEV_RELOAD`

Set to `true`, `1`, or `yes` to enable Uvicorn reload when starting through
`python run.py`. Development only.

## Reverse Proxy and Origin Handling

Forwarded-header trust is intentionally split between Uvicorn and the
application. Configure both layers for a proxy that does not connect through
loopback.

### `WIREBUDDY_TRUST_PROXY_HEADERS`

Docker-entrypoint switch for Uvicorn's forwarded-header processing.

Default in Docker: `1`.

### `FORWARDED_ALLOW_IPS`

Comma-separated proxy IPs or CIDRs that Uvicorn may trust for
`X-Forwarded-*`. Default in the Docker entrypoint: `127.0.0.1`.

```bash
FORWARDED_ALLOW_IPS=127.0.0.1,172.18.0.0/16
```

`*` is rejected by the Docker entrypoint.

### `TRUSTED_PROXY_CIDRS`

Application-level proxy CIDRs used for client-IP extraction and HTTPS-cookie
detection.

Default: `127.0.0.0/8,::1/128`.

### `WIREBUDDY_PUBLIC_ORIGIN`

Canonical public origin used by CSRF and passkey origin handling.

```bash
WIREBUDDY_PUBLIC_ORIGIN=https://vpn.example.com
```

### `WIREBUDDY_CSRF_ALLOWED_ORIGINS`

Comma-separated additional origins accepted by CSRF origin validation.

```bash
WIREBUDDY_CSRF_ALLOWED_ORIGINS=https://vpn.example.com
```

### `WIREBUDDY_ALLOWED_HOSTS`

Optional comma-separated Host-header allowlist. When unset, Trusted Host
middleware is not installed.

```bash
WIREBUDDY_ALLOWED_HOSTS=vpn.example.com,localhost
```

### `FORCE_HTTPS_COOKIES`

Forces the `Secure` attribute on authentication and CSRF cookies when HTTPS
detection through the proxy is unavailable.

Default: disabled.

### `WIREBUDDY_FORCE_HSTS`

Always emits HSTS even when TLS terminates at a proxy and the upstream request
appears as HTTP.

Default: disabled. HSTS is otherwise emitted when the request is detected as
HTTPS.

### `WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS`

Additional proxy CIDRs whose forwarded client IP is trusted specifically for
the public `/status` page. Loopback is trusted automatically.

```bash
WIREBUDDY_STATUS_TRUSTED_PROXY_CIDRS=192.168.1.10/32
```

### `WIREBUDDY_NODE_MTLS_PROXY_CIDRS`

Master-side CIDRs allowed to supply the node client-certificate fingerprint
header for node synchronization. Configure this only when a trusted TLS proxy
terminates node mutual TLS.

## Passkeys

### `PASSKEY_RP_ID`

Optional WebAuthn relying-party ID. When unset, WireBuddy derives it from the
request host.

### `PASSKEY_RP_NAME`

WebAuthn relying-party display name. Default: `WireBuddy`.

### `MAX_PASSKEYS_PER_USER`

Maximum registered passkeys per account. Values are clamped to `1`–`100`.

Default: `20`.

## Node Mode

### `WIREBUDDY_ENROLLMENT_TOKEN`

Required for first node enrollment. Create it from the master's **Nodes** page.
The token contains the master URL, node ID, and bootstrap API secret.

### `WIREBUDDY_ENROLLMENT_VERIFY_KEY`

HMAC key used to verify the enrollment token locally. Required for normal
first enrollment and generated alongside the enrollment token.

### `WIREBUDDY_MASTER_CA_FILE`

Optional path to a custom CA file used to verify the master's HTTPS
certificate. System CAs are used when unset.

```bash
WIREBUDDY_MASTER_CA_FILE=/app/data/certs/master-ca.pem
```

### `WIREBUDDY_NODE_SYNC_INTERVAL`

Normal synchronization interval in seconds. Minimum: `5`; default: `30`.

### `WIREBUDDY_NODE_SYNC_INTERVAL_FAST`

Fallback interval while SSE is disconnected. Minimum: `1`; default: `5`.

### `WIREBUDDY_ENROLLMENT_RETRY_ATTEMPTS`

Enrollment retries after transient failures. Minimum: `1`; default: `3`.

### `WIREBUDDY_NO_FIREWALL_FIX`

Disables the node's automatic DNS-related firewall correction when set to
`1`, `true`, or `yes`.

Default: disabled, so the correction is active.

### Node Development Overrides

The following switches weaken enrollment or transport validation and are for
isolated development/migration scenarios only:

- `WIREBUDDY_ALLOW_INSECURE_MASTER_HTTP=1`
- `WIREBUDDY_ALLOW_UNVERIFIED_ENROLLMENT_TOKEN=1`
- `WIREBUDDY_ALLOW_LEGACY_NODE_SECRET=1`

Do not enable them in production.

`WIREBUDDY_MASTER_URL` is not read by the current node daemon; the master URL
is carried in the enrollment token and then persisted in node state.

## GeoIP

### `WIREBUDDY_GEOIP_DB_PATH`

Explicit GeoLite2 City database path. Default:
`<WIREBUDDY_DATA_DIR>/geolite2/GeoLite2-City.mmdb`.

### `WIREBUDDY_ASN_DB_PATH`

Explicit GeoLite2 ASN database path. Default:
`<WIREBUDDY_DATA_DIR>/geolite2/GeoLite2-ASN.mmdb`.

### `WIREBUDDY_GEOIP_CITY_DOWNLOAD_URL`

Optional HTTPS download URL for the City database.

### `WIREBUDDY_GEOIP_ASN_DOWNLOAD_URL`

Optional HTTPS download URL for the ASN database.

### `WIREBUDDY_GEOIP_ALLOWED_HOSTS`

Additional comma-separated HTTPS hosts allowed for custom GeoIP URLs and
redirects. The built-in GitHub hosts remain allowed.

### `WIREBUDDY_GEOIP_CACHE_SIZE`

In-memory GeoIP lookup cache size, clamped to `128`–`65536`.

Default: `4096`.

## Security and Runtime Tuning

### `WIREBUDDY_CLEANUP_STALE_INTERFACES`

Opt-in cleanup of active WireBuddy-managed WireGuard interfaces that no longer
have matching configuration files. Disabled by default because cleanup is
destructive.

### `WIREBUDDY_MANAGE_RESOLV_CONF`

Allows WireBuddy to point `/etc/resolv.conf` at its managed Unbound resolver.

Default: disabled.

### `WIREBUDDY_RATE_LIMIT_UI_HEAVY`

SlowAPI rate string for expensive UI routes. Default: `60/minute`.

### Login Lockout Tuning

Login lockouts use three policies. Defaults are:

| Variable | Default |
|---|---:|
| `WIREBUDDY_LOGIN_IP_MIN_FAILURES` | `5` |
| `WIREBUDDY_LOGIN_IP_BASE_LOCKOUT_SECONDS` | `30` |
| `WIREBUDDY_LOGIN_IP_MAX_LOCKOUT_SECONDS` | `86400` |
| `WIREBUDDY_LOGIN_USER_IP_MIN_FAILURES` | `3` |
| `WIREBUDDY_LOGIN_USER_IP_BASE_LOCKOUT_SECONDS` | `30` |
| `WIREBUDDY_LOGIN_USER_IP_MAX_LOCKOUT_SECONDS` | `3600` |
| `WIREBUDDY_LOGIN_USERNAME_MIN_FAILURES` | `20` |
| `WIREBUDDY_LOGIN_USERNAME_BASE_LOCKOUT_SECONDS` | `60` |
| `WIREBUDDY_LOGIN_USERNAME_MAX_LOCKOUT_SECONDS` | `300` |

These values must be positive integers. Route-level request limits remain
defined by the application.

### `WIREBUDDY_PBKDF2_ITERATIONS`

PBKDF2 work factor used by vault key derivation. Default: `480000`; values are
clamped to `310000`–`2000000`.

Changing this value after encrypted data has been written can prevent existing
vault values from being decrypted. Treat it as an immutable deployment choice.

### `WIREBUDDY_DEPLOYMENT_ID`

Optional deployment-specific vault derivation context. Changing or removing it
after encrypted values exist makes those values unreadable.

### `WIREBUDDY_RUNTIME_DIR`

Directory for the process banner lock. Default: `/run/wirebuddy`.

## Development and CI

### `WIREBUDDY_SKIP_NETWORK_CHECK`

Skips Docker host-network verification. Use only in tests or CI; production
Compose does not set it.

### `WIREBUDDY_TEST_MODE` and `WIREBUDDY_MIN_GEOIP_SIZE`

Relax GeoIP fixture size checks for tests. They are not production settings.

### `TESTING`

Used by test helpers and passkey test paths. Do not enable in production.

## Settings Managed in the UI

The following are database settings, not environment variables:

- GUI port and localhost-only binding (unless overridden by
  `WIREBUDDY_PORT`/`WIREBUDDY_HOST` in Docker)
- Swagger enablement
- public status-page enablement
- WireGuard, DNS, speed-test, backup, and retention settings

Variables such as `SWAGGER_ENABLED`, `SESSION_COOKIE_*`, `RATELIMIT_*`,
`CORS_ORIGINS`, `HOST`, `PORT`, and `WORKERS` are not read by the current
application.

## Precedence

### Local `python run.py`

1. Existing process environment
2. Root `.env`
3. Compatibility `settings.env`
4. Application defaults and database settings

### Docker Compose

1. Compose `environment` entries
2. Values interpolated from the file supplied with `--env-file`
3. Image/entrypoint defaults and database settings

## Verifying Effective Configuration

```bash
docker compose --env-file .env -f docker/docker-compose.yml config
docker compose --env-file .env -f docker/docker-compose.yml exec wirebuddy env | sort
```

Be careful when sharing this output because it contains the secret key and
possibly enrollment credentials.

## Related

- [Docker Setup](../getting-started/docker.md)
- [Security Configuration](security.md)
- [Multi-Node Deployment](../features/multi-node.md)
