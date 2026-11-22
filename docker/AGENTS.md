<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# docker

## Purpose
Container packaging for WireBuddy: a multi-stage Dockerfile (Python 3.14-slim, wireguard-tools built from upstream source), the entrypoint that decides between master and node mode, and two compose files (full master deployment and a minimal cluster node). The image ships on Docker Hub as `giiibates/wirebuddy` for linux/amd64 and linux/arm64 and relies on the Docker host kernel for WireGuard.

## Key Files
| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build: wheel builder (dependencies read from `pyproject.toml` via `tomllib`; it needs git and the BuildKit secret `python_libraries_token` for the git-pinned `gillbates-*` packages, so `docker build` takes `--secret id=python_libraries_token,src=<token file>`; the runtime stage installs the wheels by name, without git or token, and import-checks every `gillbates_*` module, so a new shared package must be added to that check), wireguard-tools builder (upstream git ref), runtime image with unbound, iptables, sqlite3 etc.; exposes 8000/tcp, 51820/udp, 53/udp+tcp, defines HEALTHCHECK via `healthcheck.sh`, `ENTRYPOINT ["/entrypoint.sh"]`. Build args: `PYTHON_BASE`, `WIREGUARD_TOOLS_REF`, `APT_CACHE_DATE`, `APP_VERSION`, `BUILD_DATE`, `VCS_REF` |
| `entrypoint.sh` | Bash entrypoint. `prepare_geolite2_dir` first creates `/app/data/geolite2` (existing files and symlinks left alone); then `SERVER_MODE=node` execs `app.node.daemon.run()`; `master` reads `gui_localhost_only`/`gui_port` from the SQLite `settings` table (validating host, port, timeout, failing closed on read errors), applies `WIREBUDDY_HOST`/`WIREBUDDY_PORT` and execs `python -m app.server` — which decides HTTP vs built-in HTTPS from `gui_https_enabled` and writes `/run/wirebuddy/listener.env`; any other mode exits with an error |
| `healthcheck.sh` | Image HEALTHCHECK (`/usr/local/bin/wirebuddy-healthcheck`): probes `/ready` on exactly the scheme/host/port in `/run/wirebuddy/listener.env`; never reads the DB and never falls back from https to http |
| `docker-compose.yml` | Master deployment: host networking, `cap_drop: ALL` plus NET_ADMIN/NET_BIND_SERVICE/SETUID/SETGID/CHOWN/DAC_OVERRIDE/KILL (each verified as required: unbound port 53, user switch, chown of query log/config, root writes into unbound-owned paths, root signals the unbound process for reload/stop), `init: true`, `pids_limit: 512`, no device mounts (kernel WireGuard needs no `/dev/net/tun`; the image ships no userspace implementation), `WIREBUDDY_HOST`/`WIREBUDDY_PUBLIC_ORIGIN` passed through (empty = entrypoint default), `./data:/app/data`, no healthcheck override (uses the image's); requires `WIREBUDDY_SECRET_KEY` from `.env` (`${VAR:?}`) |
| `docker-compose.node.yml` | Cluster node deployment: `SERVER_MODE=node`, only NET_ADMIN, `init: true`, `pids_limit: 256`, no device mounts, requires `WIREBUDDY_ENROLLMENT_TOKEN`; `WIREBUDDY_ENROLLMENT_VERIFY_KEY` is optional after enrollment (`:-`), healthcheck `pgrep -f app.node.daemon` (overrides the image HEALTHCHECK), smaller log rotation |
| `apt-no-distro-wireguard.pref` | APT pin (priority -1) that blocks Debian `wireguard`, `wireguard-tools`, `wireguard-dkms`; the Dockerfile asserts the pin is effective |
| `README_Docker.md` | Docker Hub description, as short as the root `README.md`: header, screenshots, features, getting started, link to the docs, license. Compose, env vars, volumes and requirements live only in `docs/getting-started/docker.md` and `docs/configuration/environment.md` |

## For AI Agents

### Working In This Directory
- Dockerfile `COPY`s from the repo root (build context is `/opt/wirebuddy`, e.g. `docker/apt-no-distro-wireguard.pref`, `pyproject.toml`); do not build with `docker/` as context.
- Dependencies come from `pyproject.toml` `[project] dependencies`, not `requirements.txt`; keep it that way.
- Never install Debian WireGuard packages; keep the APT pin and the assertion loop in the Dockerfile.
- Compose files use `${VAR:?message}` for required secrets; never put real secret values in them or in `README_Docker.md`.
- Keep the capability set minimal; node mode intentionally has fewer capabilities than master.
- Changes to env vars, ports or volumes must be mirrored in `docs/getting-started/docker.md` and `docs/configuration/environment.md`. Keep `README_Docker.md` short and do not copy them back into it.

### Testing Requirements
- CI (`.github/workflows/docker-build.yml`) builds per architecture and smoke-tests master and node mode, then records the installed toolchain versions and runs a Trivy scan; reproduce locally with `docker build --secret id=python_libraries_token,env=PYTHON_LIBRARIES_TOKEN -f docker/Dockerfile .` and `docker compose -f docker/docker-compose.yml config`.
- `.github/workflows/ci.yml` gates every PR on `bash -n` and `shellcheck` of `docker/entrypoint.sh` and `docker/healthcheck.sh`, and on `docker build --check -f docker/Dockerfile .` (BuildKit lint, no build step); run them after editing any of these files.

### Common Patterns
- Bash uses `set -euo pipefail`, small `is_valid_*` validators and allow-listed keys for sqlite lookups.
- Image metadata via OCI labels from `APP_VERSION`, `BUILD_DATE`, `VCS_REF` build args.
- **Rolling inputs default to "current", and a release pins them.** `PYTHON_BASE` (a plain tag), `WIREGUARD_TOOLS_REF` (the `master` branch) and `APT_CACHE_DATE` (unset) are what a local `docker build` wants. The release workflow resolves all three once in its `meta` job — base image by digest, wireguard-tools to a commit SHA, the apt layer keyed on a date — and passes them to both architecture builds. Resolving them per build would let amd64 and arm64 reach those layers minutes apart and ship different toolchains inside one manifest; `create-manifest` has a parity gate that fails the release if they do. Add a new rolling input the same way: an `ARG` with a "current" default here, resolved once there.
- `APT_CACHE_DATE` specifically exists so a cached apt layer cannot skip `apt-get upgrade`, which is the only step that moves the OS packages forward once the base image is digest-pinned.

## Dependencies

### Internal
- `app/` (copied into the image; `app.node.daemon` is the node entry), `pyproject.toml` (version comes in via the `APP_VERSION` build arg), `.github/workflows/docker-build.yml`.

### External
- `python:3.14-slim`, upstream `wireguard-tools` (git.zx2c4.com), Debian packages (unbound, dns-root-data, iptables, iproute2, conntrack, sqlite3, curl, openresolv), Docker Hub, WireGuard kernel support on the host.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
