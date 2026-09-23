<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# docs

## Purpose
Sources of the WireBuddy documentation site, built with MkDocs Material and deployed to GitHub Pages (https://gill-bates.github.io/wirebuddy/). `docs_dir` is this directory itself (`docs_dir: .`) and the site is written to `../site`. Content is grouped into getting started, features, configuration, security, API and development guides.

## Key Files
| File | Description |
|------|-------------|
| `mkdocs.yml` | MkDocs Material config: site metadata, light/dark palette (indigo), navigation features, plugins and the nav tree; built with `--strict` in CI |
| `index.md` | Landing page: what WireBuddy is, key features, quick start snippet, screenshots, security-first summary, community links |
| `troubleshooting.md` | Symptom-driven fixes: container start, web UI/reverse proxy, built-in HTTPS, peer handshake, no internet through tunnel, DNS resolution/blocking, empty traffic/GeoIP analytics |
| `stylesheets/extra.css` | Custom theme tweaks (`--wb-primary`/`--wb-accent`, dark-mode background colours matching the app) |
| `assets/favicon.png` | Site favicon (only file in `assets/`) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `getting-started/` | Installation, quick start, Docker setup, first steps, see `getting-started/AGENTS.md` |
| `features/` | Per-feature user guides (WireGuard, DNS, multi-node, backup, ...), see `features/AGENTS.md` |
| `configuration/` | Settings and environment variable references, see `configuration/AGENTS.md` |
| `security/` | Security model, authentication, passkeys, rate limiting, hardening, see `security/AGENTS.md` |
| `api/` | REST API overview, authentication, endpoints, see `api/AGENTS.md` |
| `development/` | Architecture, setup, contributing, see `development/AGENTS.md` |

## For AI Agents

### Working In This Directory
- Every new page must be added to the `nav` in `mkdocs.yml`; `--strict` fails on broken links and missing nav targets.
- `docs/changelog.md` and `docs/license.md` are generated in CI from the root `CHANGELOG.md` and `LICENSE`; do not create or commit them by hand.
- Some pages carry `title:` front matter, others rely on the first `#` heading; follow the neighbouring page.
- Never include real secrets or credentials in examples; use placeholders (e.g. `WIREBUDDY_SECRET_KEY` generation commands).
- Keep docs in sync with behaviour: env vars (`app/`), ports and volumes (`docker/`), API routes (`app/api/`).

### Testing Requirements
- `mkdocs build -f docs/mkdocs.yml --strict` (docs extra from `pyproject.toml`); CI also runs lychee link checks on the built site.

### Common Patterns
- Task-oriented Markdown with fenced shell/YAML examples, admonitions, "Next Steps" links at the end of guides.

## Dependencies

### Internal
- Root `CHANGELOG.md`, `LICENSE`, `README.md`, `pyproject.toml` (docs extra), `.github/workflows/docs-build.yml`, `.github/img/` screenshots.

### External
- MkDocs, mkdocs-material and plugins (search, minify, git-revision-date-localized; see `pyproject.toml`), GitHub Pages, lychee.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
