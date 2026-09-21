# syntax=docker/dockerfile:1

# The base image for every stage, in one place so a release can pin it to a
# digest. Left as a plain tag by default, which is what a local `docker build`
# wants; .github/workflows/docker-build.yml resolves
# python:3.13-slim@sha256:... once in its meta job and passes it to both
# architecture builds, so amd64 and arm64 cannot end up on two different
# pushes of the same tag.
ARG PYTHON_BASE=python:3.13-slim

FROM ${PYTHON_BASE} AS builder

WORKDIR /build

# pyproject.toml is the single dependency manifest (it replaced
# requirements.txt). Only the [project] dependencies are materialised into a
# flat requirements file here - tomllib is stdlib in 3.13, so no extra
# build-time tool is needed to read them back out.
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    python -c 'import tomllib; print("\n".join(tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]))' \
        > requirements.txt && \
    pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt && \
    rm -f requirements.txt

# Build the current upstream wireguard-tools tree. BuildKit resolves the mutable
# Git ref on every build, so a new upstream commit invalidates this layer
# instead of silently reusing an old distribution package.
FROM ${PYTHON_BASE} AS wireguard-tools-builder

WORKDIR /build

# Defaults to the branch, which is the right thing for a local build: "give me
# current upstream". A release must not leave it at that, because the amd64 and
# arm64 jobs are separate runners that reach this layer minutes apart and would
# each resolve "master" on its own - an upstream commit landing in that window
# would put two different wg builds in the two halves of one manifest. The
# release workflow resolves the branch to a commit SHA once and passes it here.
ARG WIREGUARD_TOOLS_REF=master

ADD --keep-git-dir=true https://git.zx2c4.com/wireguard-tools.git#${WIREGUARD_TOOLS_REF} /build/wireguard-tools

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
# PYTHON_BASE is only pinned to a digest when docker-build.yml's meta job
# resolves it and passes it as a build arg (see the ARG PYTHON_BASE comment
# above). A plain `docker build` without that arg uses the mutable
# python:3.13-slim tag, which is intentional for local iteration but is not
# reproducible; only CI-built release images carry the digest pin.
FROM ${PYTHON_BASE} AS runtime-base

ARG APP_VERSION
ARG BUILD_DATE
ARG VCS_REF

# Cache buster for the apt layer below. Without it, a release whose apt layer is
# restored from the build cache silently skips `apt-get upgrade` and ships the
# security patches of whenever that layer was first built - which defeats the
# point of running the upgrade at all. Resolved once per release in the meta job
# of docker-build.yml so both architectures key this layer on the same value; a
# date rather than a timestamp, so re-running one release still reuses the layer.
ARG APT_CACHE_DATE

LABEL maintainer="Gill-Bates <github.com/Gill-Bates>" \
    description="WireBuddy - Lightweight WireGuard Management WebUI" \
    org.opencontainers.image.version="${APP_VERSION}" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.licenses="MIT" \
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
    # Pull latest security patches (e.g. openssl). The base image is pinned to a
    # digest for a release build (see ARG PYTHON_BASE), so this is the only step
    # that moves the OS packages forward - and APT_CACHE_DATE above is what stops
    # a cached layer from skipping it.
    echo "apt cache date: ${APT_CACHE_DATE:-unset}"; \
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
COPY pyproject.toml .
RUN python -c 'import tomllib; print("\n".join(tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]))' \
        > requirements.txt && \
    pip install --no-cache-dir --no-compile --no-index --find-links=/wheels -r requirements.txt && \
    rm -rf /wheels requirements.txt && \
    # pip is a build-time tool, not needed to run the app; removing it also
    # drops its vendored setuptools/msgpack copies from the shipped image.
    pip uninstall -y pip

# Copy only application code (relies on .dockerignore)
COPY app ./app
# pyproject.toml is already in place from the dependency layer above; it also
# carries the release version app/utils/version.py reads at runtime.
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

# Health check using curl (faster than Python). Uses WIREBUDDY_PORT so a
# port override (env var or a compose file that doesn't override
# HEALTHCHECK) still probes the port uvicorn actually bound. Does not know
# about a gui_port persisted in the database without WIREBUDDY_PORT set;
# compose files pin WIREBUDDY_PORT precisely to avoid that gap.
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl --fail --silent --show-error --max-time 5 \
        "http://127.0.0.1:${WIREBUDDY_PORT:-8000}/api/system/status" || exit 1

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENV UVICORN_GRACEFUL_SHUTDOWN_TIMEOUT=8

# Timezone (default: UTC). Override with TZ=America/New_York etc.
# See: https://en.wikipedia.org/wiki/List_of_tz_database_time_zones
ENV TZ=Etc/UTC

# X-Forwarded-For / X-Real-IP proxy header handling.
#
# Single variable for both uvicorn's --forwarded-allow-ips (set in
# entrypoint.sh) and the application-level proxy-trust checks in
# app/utils/config.py, app/api/frontend_status.py and app/api/nodes_sync.py.
# Defaults to loopback only, so a reverse proxy on the same host (Caddy,
# nginx) is trusted out of the box while non-loopback sources are not. For a
# proxy on a different host or in a separate container network, set this to
# that proxy's IP(s)/CIDR(s):
#   WIREBUDDY_TRUSTED_PROXIES=172.18.0.2,172.18.0.3
ENV WIREBUDDY_TRUSTED_PROXIES="127.0.0.1,::1"

# Run with proxy headers for reverse proxy support (Caddy/Nginx)
COPY --chmod=0755 docker/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
