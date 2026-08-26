# syntax=docker/dockerfile:1

FROM python:3.13-slim@sha256:7e3a6aca9d74f93cca21a91d86a8dad8c34749afd5b4a98ee481c9c47b9f5ed4 AS builder

WORKDIR /build

# Install build dependencies and create wheels
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt

# Build the current upstream wireguard-tools master branch. BuildKit resolves
# the mutable Git ref on every build, so a new upstream commit invalidates this
# layer instead of silently reusing an old distribution package.
FROM python:3.13-slim@sha256:7e3a6aca9d74f93cca21a91d86a8dad8c34749afd5b4a98ee481c9c47b9f5ed4 AS wireguard-tools-builder

WORKDIR /build

ADD --keep-git-dir=true https://git.zx2c4.com/wireguard-tools.git#master /build/wireguard-tools

# git is required so the Makefile's `git describe --dirty` call can embed a
# real WIREGUARD_TOOLS_VERSION; without it the lookup fails silently and the
# binary ships with no version string despite --keep-git-dir=true above.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git; \
    mkdir -p /out; \
    make -C /build/wireguard-tools/src -j"$(nproc)"; \
    make -C /build/wireguard-tools/src \
        DESTDIR=/out \
        PREFIX=/usr \
        WITH_BASHCOMPLETION=no \
        WITH_SYSTEMDUNITS=no \
        WITH_WGQUICK=yes \
        install; \
    strip /out/usr/bin/wg; \
    /out/usr/bin/wg --version; \
    test -x /out/usr/bin/wg-quick

# ─────────────────────────────────────────────────────────────
FROM python:3.13-slim@sha256:7e3a6aca9d74f93cca21a91d86a8dad8c34749afd5b4a98ee481c9c47b9f5ed4 AS runtime-base

ARG APP_VERSION
ARG BUILD_DATE
ARG VCS_REF

LABEL maintainer="Gill-Bates <github.com/Gill-Bates>" \
    description="WireBuddy - Lightweight WireGuard Management WebUI" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.licenses="AGPL-3.0" \
    org.opencontainers.image.source="https://github.com/Gill-Bates/wirebuddy"

WORKDIR /app

# Never install Debian's WireGuard packages. The userspace tools are copied
# from the official upstream build stage below; the host supplies WireGuard.
COPY docker/apt-no-distro-wireguard.pref /etc/apt/preferences.d/no-distro-wireguard.pref

# Install runtime dependencies and assert that the APT pin is effective.
RUN set -eux; \
    apt-get update; \
    for package in wireguard wireguard-tools wireguard-dkms; do \
        candidate="$(apt-cache policy "$package" | awk '/Candidate:/ { print $2 }')"; \
        test "$candidate" = "(none)"; \
    done; \
    # Pull latest security patches (e.g. openssl) even though the base image
    # tag+digest above is pinned for reproducibility.
    apt-get upgrade -y; \
    apt-get install -y --no-install-recommends \
        bash \
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
        librespeed-cli; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# Install wg and wg-quick from the current official upstream source tree.
COPY --from=wireguard-tools-builder /out/ /
RUN wg --version && \
    command -v wg-quick >/dev/null

# Keep the dependency/toolchain layer independently buildable for validation.
FROM runtime-base AS runtime

ARG VCS_REF

# Install Python dependencies from pre-built wheels
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile --no-index --find-links=/wheels -r requirements.txt && \
    rm -rf /wheels requirements.txt && \
    # pip is a build-time tool, not needed to run the app; removing it also
    # drops its vendored setuptools/msgpack copies from the shipped image.
    pip uninstall -y pip

# Copy only application code (relies on .dockerignore)
COPY app ./app
COPY VERSION .
# Generated from VCS_REF instead of COPY-ing a BUILD_INFO file so local
# `docker build` works without a CI-only pre-step. Falls back to "dev" when
# no VCS_REF is passed (see app/utils/version.py).
RUN printf '%s' "${VCS_REF:-dev}" > BUILD_INFO
COPY LICENSE .
COPY CHANGELOG.md .

# Note: GeoIP databases (GeoLite2-City.mmdb, GeoLite2-ASN.mmdb) are
# automatically downloaded on first startup and updated weekly at runtime.
# No need to bake them into the image.

# Note: Vendor fonts (Material Icons, Roboto Flex, Noto Serif) are committed
# under app/static/vendor/fonts/ and copied in with the app code above.

# Note: Country flags are served from CDN (jsdelivr.net/npm/flag-icons)
# to reduce image size and simplify updates.

# Create data and log directories + DNSSEC root key
# Note: Container runs as root for WireGuard/iptables commands
# Security is enforced via capabilities + no-new-privileges in compose
RUN set -eux; \
    mkdir -p /app/data /var/log/unbound /etc/wireguard /var/lib/unbound; \
    chown -R unbound:unbound /var/log/unbound /var/lib/unbound; \
    install -o unbound -g unbound -m 0644 \
        /usr/share/dns/root.key \
        /var/lib/unbound/root.key; \
    test -s /var/lib/unbound/root.key

# Persistent data volume
VOLUME ["/app/data"]

# Expose web UI, WireGuard, and DNS ports
EXPOSE 8000/tcp
EXPOSE 51820/udp
EXPOSE 53/udp
EXPOSE 53/tcp

# Health check using curl (faster than Python)
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl --fail --silent --show-error --max-time 5 \
        http://127.0.0.1:8000/api/system/status || exit 1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

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
COPY --chmod=0755 docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
