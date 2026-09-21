<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# .github

## Purpose
GitHub repository automation and assets: CI/CD workflows (PR gate, multi-arch Docker release, documentation deployment, Playwright UI audit), Renovate dependency policy, README screenshots and logos, and the Copilot-style agent prompt files used for code review and Python development.

## Key Files
| File | Description |
|------|-------------|
| `renovate.json` | Renovate config: `config:best-practices`, weekly schedule (before 6am Monday, Europe/Berlin), max 3 open PRs; auto-merges minor/patch GitHub Actions with digest pinning and 3-day release age, pins Docker digests, groups Python deps for manual review, keeps trivy-action always current, majors labelled `breaking-change`, vulnerability alerts labelled `security` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `agents/` | Agent prompt files (review suite and PythonDev), see `agents/AGENTS.md` |
| `workflows/` | GitHub Actions pipelines: `ci.yml` (PR gate), `docker-build.yml` (tagged release), `docs-build.yml` (Pages), `ui-audit.yml` (non-blocking Playwright audit). See `workflows/AGENTS.md` |
| `img/` | README screenshots (`screen_1.jpeg`–`screen_6.jpeg`) and logos (`wirebuddy_black.svg`, `wirebuddy_white.svg`); binary/asset only, no AGENTS.md |

## For AI Agents

### Working In This Directory
- Workflow actions are pinned (some by commit SHA for supply-chain safety); keep pins when editing.
- Do not commit secrets; workflows read Docker Hub credentials from repository secrets. The UI audit generates its own secret key and admin password per run, so neither is ever stored.
- Renovate config is strict JSON (4-space indent).
- `ci.yml` is the only workflow that gates a PR. `ui-audit.yml` is deliberately `continue-on-error`, and `docker-build.yml` only runs on tags — keep that division when adding checks: deterministic ones belong in `ci.yml`, timing-sensitive browser work does not.

### Testing Requirements
- No local test runner for the workflows themselves; validate YAML syntax and rely on the PR run. Validate `renovate.json` with `npx renovate-config-validator` if available.
- The steps inside them are reproducible locally — see `workflows/AGENTS.md`.

### Common Patterns
- Least-privilege `permissions:` blocks per workflow/job, `concurrency` groups, explicit `timeout-minutes`, named runner images rather than `ubuntu-latest`.

## Dependencies

### Internal
- `docker/Dockerfile`, `docker/entrypoint.sh`, `docs/mkdocs.yml`, `pyproject.toml`, `CHANGELOG.md`, `LICENSE`, `.trivyignore`, `run.py`, `tests/`, `tools/`.

### External
- GitHub Actions, Docker Hub, GitHub Pages, Renovate, Trivy, Playwright.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
