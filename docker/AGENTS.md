<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# docker

## Purpose
Container packaging for WireBuddy: a multi-stage Dockerfile (Python 3.13-slim, wireguard-tools built from upstream source), the entrypoint that decides between master and node mode, and two compose files (full master deployment and a minimal cluster node). The image ships on Docker Hub as `giiibates/wirebuddy` for linux/amd64 and linux/arm64 and relies on the Docker host kernel for WireGuard.

## Key Files
| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build: wheel builder (dependencies read from `pyproject.toml` via `tomllib`), wireguard-tools builder (upstream git ref), runtime image with unbound, iptables, sqlite3 etc.; exposes 8000/tcp, 51820/udp, 53/udp+tcp, defines HEALTHCHECK, `ENTRYPOINT ["/entrypoint.sh"]`. Build args: `PYTHON_BASE`, `WIREGUARD_TOOLS_REF`, `APT_CACHE_DATE`, `APP_VERSION`, `BUILD_DATE`, `VCS_REF` |
| `entrypoint.sh` | Bash entrypoint. `SERVER_MODE=node` execs `app.node.daemon.run()`; `master` reads `gui_localhost_only`/`gui_port` from the SQLite `settings` table (validating host, port, timeout) and starts uvicorn; any other mode exits with an error |
| `docker-compose.yml` | Master deployment: host networking, `cap_drop: ALL` plus NET_ADMIN/NET_BIND_SERVICE/SETUID/SETGID/CHOWN/DAC_OVERRIDE, `/dev/net/tun`, `./data:/app/data`, curl-based `/health` healthcheck; requires `WIREBUDDY_SECRET_KEY` |
| `docker-compose.node.yml` | Cluster node deployment: `SERVER_MODE=node`, only NET_ADMIN, requires `WIREBUDDY_ENROLLMENT_TOKEN` and `WIREBUDDY_ENROLLMENT_VERIFY_KEY`, healthcheck disabled, smaller log rotation |
| `apt-no-distro-wireguard.pref` | APT pin (priority -1) that blocks Debian `wireguard`, `wireguard-tools`, `wireguard-dkms`; the Dockerfile asserts the pin is effective |
| `README_Docker.md` | Docker Hub description: features, quick start, compose, env vars, volumes, requirements, WireGuard source policy |

## For AI Agents

### Working In This Directory
- Dockerfile `COPY`s from the repo root (build context is `/opt/wirebuddy`, e.g. `docker/apt-no-distro-wireguard.pref`, `pyproject.toml`); do not build with `docker/` as context.
- Dependencies come from `pyproject.toml` `[project] dependencies`, not `requirements.txt`; keep it that way.
- Never install Debian WireGuard packages; keep the APT pin and the assertion loop in the Dockerfile.
- Compose files use `${VAR:?message}` for required secrets; never put real secret values in them or in `README_Docker.md`.
- Keep the capability set minimal; node mode intentionally has fewer capabilities than master.
- Changes to env vars, ports or volumes must be mirrored in `README_Docker.md` and `docs/getting-started/docker.md`, `docs/configuration/environment.md`.

### Testing Requirements
- CI (`.github/workflows/docker-build.yml`) builds per architecture and smoke-tests master and node mode, then records the installed toolchain versions and runs a Trivy scan; reproduce locally with `docker build -f docker/Dockerfile .` and `docker compose -f docker/docker-compose.yml config`.
- `.github/workflows/ci.yml` gates every PR on `bash -n docker/entrypoint.sh` and `docker build --check -f docker/Dockerfile .` — run both after editing either file. `--check` is BuildKit's linter: it resolves stages, ARG/ENV references and `COPY --from` targets without running a build step, so it is seconds rather than minutes.

### Common Patterns
- Bash uses `set -euo pipefail`, small `is_valid_*` validators and allow-listed keys for sqlite lookups.
- Image metadata via OCI labels from `APP_VERSION`, `BUILD_DATE`, `VCS_REF` build args.
- **Rolling inputs default to "current", and a release pins them.** `PYTHON_BASE` (a plain tag), `WIREGUARD_TOOLS_REF` (the `master` branch) and `APT_CACHE_DATE` (unset) are what a local `docker build` wants. The release workflow resolves all three once in its `meta` job — base image by digest, wireguard-tools to a commit SHA, the apt layer keyed on a date — and passes them to both architecture builds. Resolving them per build would let amd64 and arm64 reach those layers minutes apart and ship different toolchains inside one manifest; `create-manifest` has a parity gate that fails the release if they do. Add a new rolling input the same way: an `ARG` with a "current" default here, resolved once there.
- `APT_CACHE_DATE` specifically exists so a cached apt layer cannot skip `apt-get upgrade`, which is the only step that moves the OS packages forward once the base image is digest-pinned.

## Dependencies

### Internal
- `app/` (copied into the image; `app.node.daemon` is the node entry), `pyproject.toml` (version comes in via the `APP_VERSION` build arg), `.github/workflows/docker-build.yml`.

### External
- `python:3.13-slim`, upstream `wireguard-tools` (git.zx2c4.com), Debian packages (unbound, iptables, iproute2, conntrack, sqlite3, curl, openresolv), Docker Hub, `/dev/net/tun` on the host.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
