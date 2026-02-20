FROM python:3.13-slim AS builder

WORKDIR /build

# Install build dependencies and create wheels
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt

# ─────────────────────────────────────────────────────────────
FROM python:3.13-slim AS runtime

ARG APP_VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL maintainer="Gill-Bates <github.com/Gill-Bates>"
LABEL description="WireBuddy - Lightweight WireGuard Management WebUI"
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${VCS_REF}"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wireguard-tools \
        iptables \
        iproute2 \
        unbound \
        dns-root-data \
        openresolv \
        procps \
        curl \
        ca-certificates \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies from pre-built wheels
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --no-compile --no-index --find-links=/wheels -r requirements.txt && \
    rm -rf /wheels

# Copy only application code (relies on .dockerignore)
COPY app ./app
COPY VERSION .
COPY BUILD_INFO* .
COPY LICENSE .
COPY CHANGELOG.md .

# Note: GeoIP databases (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb) are
# automatically downloaded on first startup and updated weekly at runtime.
# No need to bake them into the image.

# Download country flag SVGs (4×3) from lipis/flag-icons for local serving
RUN mkdir -p /app/app/static/vendor/images/flags && \
    curl -sL https://github.com/lipis/flag-icons/archive/refs/heads/main.tar.gz | \
    tar -xz --strip-components=3 -C /app/app/static/vendor/images/flags flag-icons-main/flags/4x3/ && \
    echo "Downloaded $(ls /app/app/static/vendor/images/flags/*.svg 2>/dev/null | wc -l) flag SVGs"

# Create data and log directories + DNSSEC root key
# Note: Container runs as root for WireGuard/iptables commands
# Security is enforced via capabilities + no-new-privileges in compose
RUN mkdir -p /data /var/log/unbound /etc/wireguard /var/lib/unbound && \
    chown -R unbound:unbound /var/log/unbound /var/lib/unbound && \
    # Try unbound-anchor first, fallback to dns-root-data package
    (/usr/sbin/unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || \
     cp /usr/share/dns/root.key /var/lib/unbound/root.key 2>/dev/null || true) && \
    [ -f /var/lib/unbound/root.key ] && chown unbound:unbound /var/lib/unbound/root.key || true

# Persistent data volume
VOLUME ["/data"]

# Expose web UI, WireGuard, and DNS ports
EXPOSE 8000
EXPOSE 51820/udp
EXPOSE 53/udp
EXPOSE 53/tcp

# Health check using curl (faster than Python)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/docs || exit 1

# Configurable worker count (2 for resilience, SQLite/TSDB are multi-process safe)
ENV UVICORN_WORKERS=2

# X-Forwarded-For / X-Real-IP proxy header handling.
#
# Default is empty (disabled) to prevent IP spoofing attacks that bypass
# rate limiting. Only pods/containers behind a KNOWN reverse proxy should
# enable this by setting FORWARDED_ALLOW_IPS to the proxy IP(s):
#   FORWARDED_ALLOW_IPS=172.18.0.2,172.18.0.3
#
# For direct exposure to the internet (no proxy), leave blank.
ENV FORWARDED_ALLOW_IPS=""

# Run with proxy headers for reverse proxy support (Caddy/Nginx)
ENTRYPOINT ["sh", "-c", "exec uvicorn app:create_app --host 0.0.0.0 --port 8000 --factory --workers ${UVICORN_WORKERS} --proxy-headers --forwarded-allow-ips=${FORWARDED_ALLOW_IPS}"]
