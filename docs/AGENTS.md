<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# docs

## Purpose
Sources of the WireBuddy documentation site, built with Zensical (`classic` variant) and deployed to GitHub Pages (https://gill-bates.github.io/wirebuddy/). The configuration is the root `zensical.toml` with `docs_dir = "docs"`; the site is written to the root `site/`. `AGENTS.md` files are excluded from the site via `exclude_docs`.

## Key Files
| File | Description |
|------|-------------|
| `index.md` | Landing page (`hide: navigation`): what WireBuddy is, key features, quick start snippet, screenshots, security pointer to the Security Overview, community buttons |
| `troubleshooting.md` | Symptom-driven fixes: container start, web UI/reverse proxy, built-in HTTPS, peer handshake, no internet through tunnel, DNS, empty traffic/GeoIP analytics, database checks and backups, login/TOTP/passkeys, Let's Encrypt, bug-report data |
| `stylesheets/extra.css` | Supplies the `custom` primary/accent palette of `zensical.toml` (WireBuddy red, taken from `app/static/css/style.css`), light-red links and app-matching backgrounds in the dark scheme, grid-card and admonition tweaks |
| `assets/favicon.png` | Site favicon |

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
- Every new page must be added to the `nav` in the root `zensical.toml`; `--strict` fails on broken links and anchors.
- `docs/changelog.md` and `docs/license.md` are generated in CI from the root `CHANGELOG.md` and `LICENSE`; do not create or commit them by hand.
- Some pages carry `title:` front matter, others rely on the first `#` heading; follow the neighbouring page.
- Never include real secrets or credentials in examples; use placeholders (e.g. `WIREBUDDY_SECRET_KEY` generation commands).
- Keep docs in sync with behaviour: env vars (`app/`), ports and volumes (`docker/`), API routes (`app/api/`).

### Testing Requirements
- `zensical build --config-file zensical.toml --strict --clean` from the repository root (docs extra from `pyproject.toml`); CI also runs lychee link checks on the built site.

### Common Patterns
- Task-oriented Markdown with fenced shell/YAML examples, admonitions, "Next Steps" links at the end of guides.

## Dependencies

### Internal
- Root `zensical.toml`, `CHANGELOG.md`, `LICENSE`, `pyproject.toml` (docs extra), `.github/workflows/docs-build.yml`; `index.md` loads logos and screenshots from `.github/img/` through `raw.githubusercontent.com/.../main/` URLs, so new images render only after they reach `main`.

### External
- Zensical (pinned in the `docs` extra of `pyproject.toml`; built-in search and minify plugins), GitHub Pages, lychee. No MkDocs plugins: Zensical does not load them, so page revision dates (`git-revision-date-localized`) are not available.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
