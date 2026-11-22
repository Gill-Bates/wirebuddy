<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# getting-started

## Purpose
Onboarding path for new operators: choosing an installation method, a fast Docker-based quick start, Docker-specific setup, and the first configuration steps after login.

## Key Files
| File | Description |
|------|-------------|
| `installation.md` | Installation methods overview: Docker installation, then links to `quick-start.md` / `docker.md` for sysctl, `.env`, Compose, docker run and updating; local development, post-installation, reverse proxy tabs (Caddy reproduces the root `Caddyfile`, plus Nginx and Traefik), firewall, next steps |
| `quick-start.md` | Step-by-step: prerequisites, clone, configure `.env` (secret key generation), enable IP forwarding and conntrack accounting, start, sign in, reverse proxy; troubleshooting and updating |
| `docker.md` | Docker setup: prerequisites, compose file, included security hardening, persistent data, custom port/bind address, reverse proxy, docker run, health checks, updating, managing the container, remote node, troubleshooting |
| `first-steps.md` | After first login: replace the temporary admin password (printed once on the console at first start), set public server address, create/start an interface, add a peer, import client config, verify tunnel, optional services |

## For AI Agents

### Working In This Directory
- Commands must match `docker/docker-compose.yml`; remote-node setup is linked to `../features/multi-node.md`, not repeated here. `docker/README_Docker.md` links to `docker.md` for Compose, `docker run` and environment; it only repeats `docker pull` and `docker logs`.
- Use generated placeholder secrets only; never paste real keys.
- Pages use `title:` front matter.

### Testing Requirements
- Strict Zensical build, see `../AGENTS.md`; sanity-check documented commands against the compose file.

### Common Patterns
- Numbered steps with shell blocks, then links to the next guide.

## Dependencies

### Internal
- `docker/`, `../configuration/environment.md`, `../security/best-practices.md`, `../features/wireguard.md`, `../troubleshooting.md`.

### External
- Docker / Docker Compose, a Linux host with WireGuard kernel support.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
