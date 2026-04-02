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
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/Gill-Bates/wirebuddy"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wireguard-tools \
        iptables \
        iproute2 \
        conntrack \
        unbound \
        dns-root-data \
        openresolv \
        procps \
        curl \
        ca-certificates \
        sqlite3 \
        tzdata \
        librespeed-cli \
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

# Download vendor assets (flags + fonts) for local serving
RUN set -eux; \
    FONT_CSS_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36'; \
    mkdir -p /app/app/static/vendor/images/flags \
             /app/app/static/vendor/fonts; \
    \
    # Flags (lipis/flag-icons)
    curl -fsSL https://github.com/lipis/flag-icons/archive/refs/heads/main.tar.gz \
    | tar -xz --strip-components=3 \
        -C /app/app/static/vendor/images/flags \
        flag-icons-main/flags/4x3/; \
    echo "Downloaded $(ls /app/app/static/vendor/images/flags/*.svg | wc -l) flag SVGs"; \
    \
    # Fonts: resolve current WOFF2 asset URLs from Google Fonts CSS at build time
    MATERIAL_ICONS_URL="$(curl -fsSL -A "$FONT_CSS_UA" 'https://fonts.googleapis.com/icon?family=Material+Icons' \
        | sed -n 's/.*url(\(https:[^)]*\.woff2\)).*/\1/p' \
        | head -n1)"; \
    ROBOTO_FLEX_URL="$(curl -fsSL -A "$FONT_CSS_UA" 'https://fonts.googleapis.com/css2?family=Roboto+Flex:opsz,wght@8..144,100..1000&display=swap' \
        | sed -n 's/.*url(\(https:[^)]*\.woff2\)).*/\1/p' \
        | tail -n1)"; \
    NOTO_SERIF_URL="$(curl -fsSL -A "$FONT_CSS_UA" 'https://fonts.googleapis.com/css2?family=Noto+Serif:wght@400&display=swap' \
        | sed -n 's/.*url(\(https:[^)]*\.woff2\)).*/\1/p' \
        | tail -n1)"; \
    test -n "$MATERIAL_ICONS_URL"; \
    test -n "$ROBOTO_FLEX_URL"; \
    test -n "$NOTO_SERIF_URL"; \
    curl -fsSL -o /app/app/static/vendor/fonts/MaterialIcons.woff2 "$MATERIAL_ICONS_URL"; \
    curl -fsSL -o /app/app/static/vendor/fonts/RobotoFlex.woff2 "$ROBOTO_FLEX_URL"; \
    curl -fsSL -o /app/app/static/vendor/fonts/NotoSerif.woff2 "$NOTO_SERIF_URL"; \
    \
    echo "Downloaded fonts: \
MaterialIcons=$(stat -c%s /app/app/static/vendor/fonts/MaterialIcons.woff2)B, \
RobotoFlex=$(stat -c%s /app/app/static/vendor/fonts/RobotoFlex.woff2)B, \
NotoSerif=$(stat -c%s /app/app/static/vendor/fonts/NotoSerif.woff2)B"

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
    CMD curl -f http://localhost:8000/api/system/status || exit 1

# Web UI runs single-worker only. Values >1 are normalized to 1 in the entrypoint.
ENV UVICORN_WORKERS=1
ENV UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT=8

# Timezone (default: UTC). Override with TZ=America/New_York etc.
# See: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
ENV TZ=Etc/UTC

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
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
