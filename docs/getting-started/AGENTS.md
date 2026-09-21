<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# getting-started

## Purpose
Onboarding path for new operators: choosing an installation method, a fast Docker-based quick start, Docker-specific setup, and the first configuration steps after login.

## Key Files
| File | Description |
|------|-------------|
| `installation.md` | Installation methods: Docker Compose (recommended), docker run, local development; post-installation, updating, reverse proxy |
| `quick-start.md` | Step-by-step: prerequisites, clone, configure `.env` (secret key generation), enable IP forwarding, start and sign in |
| `docker.md` | Docker setup: prerequisites, compose file, included security hardening, persistent data, custom port/bind address, reverse proxy, docker run |
| `first-steps.md` | After first login: replace temporary password, set public server address, create/start an interface, add a peer, import client config, verify tunnel, optional services |

## For AI Agents

### Working In This Directory
- Commands must match `docker/docker-compose.yml` and `docker/README_Docker.md`; update all together.
- Use generated placeholder secrets only; never paste real keys.
- Pages use `title:` front matter.

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict`; sanity-check documented commands against the compose file.

### Common Patterns
- Numbered steps with shell blocks, then links to the next guide.

## Dependencies

### Internal
- `docker/`, `../configuration/environment.md`, `../security/best-practices.md`, `../features/wireguard.md`, `../troubleshooting.md`.

### External
- Docker / Docker Compose, a Linux host with WireGuard kernel support.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
