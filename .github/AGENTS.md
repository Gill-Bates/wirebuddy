<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# .github

## Purpose
GitHub repository automation and assets: CI/CD workflows (PR gate, multi-arch Docker release, weekly rescan of the published image, documentation deployment), their tested helper scripts, the Renovate, actionlint and zizmor configuration, and the README screenshots and logos.

## Key Files
| File | Description |
|------|-------------|
| `actionlint.yaml` | actionlint config declaring the `ubuntu-26.04` and `ubuntu-26.04-arm` runner labels that older actionlint releases do not know |
| `zizmor.yml` | Configuration of the zizmor job in `ci.yml`; only reasoned ignores (`self-repository` for the `./` reusable call in `docker-build.yml`, `dangerous-triggers` for the `workflow_run` in `docs-build.yml`) |
| `renovate.json` | Renovate: `config:best-practices`, Mondays before 6am (Europe/Berlin), max 3 open PRs. Only minor/patch GitHub Actions auto-merge (digest-pinned, 3-day release age); Docker digests are pinned; `pep621` Python deps, the `trivy` group (action and CLI) and majors need review. A regex manager bumps the `# renovate:`-marked tool versions in the workflows (`ci-tooling`, never auto-merged) but not `ACTIONLINT_SHA256`/`TRIVY_SHA256`: update the checksum by hand in the same PR, or the install fails closed |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `scripts/` | Tested helpers the workflows call: `ci_job_setup.py` (agent banner, job temp dirs), `ci_output.py` (shared header and level output), `trivy_report.py` (Trivy verdict with coverage proof; `--expect-ref` requires the report to describe the scanned image), `failure_issue.py` (tracking issue for a failed run), `release_tags.py` (build matrix check, `is_newest`, push digest, candidate create/verify, promote, fragment cleanup, pruning; `stable-latest`/`resolve` for `security.yml`, falling back to `latest` when no stable version tag is listed), `toolchain_parity.py` (cross-arch version parity gate), `release_notes.py` (release body from CHANGELOG, tags, index digest and Trivy reports), `release_publish.cjs` (draft-first GitHub Release with the Trivy reports as assets, used by `create-release`; verifies asset state, size and SHA-256 before and after publishing, sets `make_latest` from the Docker `latest` decision; updates a published release whose notes differ after a rerun), `test_workflow_contracts.py` (structural workflow contracts, see `workflows/AGENTS.md`) |
| `workflows/` | GitHub Actions pipelines: `ci.yml` (PR gate), `docker-build.yml` (tagged release), `security.yml` (weekly rescan), `docs-build.yml` (Pages). See `workflows/AGENTS.md` |
| `img/` | README screenshots (`screen_1.jpeg`–`screen_6.jpeg`) and logos (`wirebuddy_black.svg`, `wirebuddy_white.svg`, `wirebuddy_dockerhub.svg` for the Docker Hub README); binary/asset only, no AGENTS.md |

## For AI Agents

### Working In This Directory
- Do not commit secrets; workflows read `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` and `RELEASE_TOKEN` from repository secrets.
- Renovate config is strict JSON (4-space indent).
- `ci.yml` is the PR gate; `docs-build.yml` also builds and scans docs-relevant PRs but deploys only from `main`. `docker-build.yml` runs only from a version tag (push or manual dispatch). Keep that division when adding checks: deterministic ones belong in `ci.yml`; the Playwright layout suite (`tests/layout/`) is the one browser check that runs in `ci.yml` (job `layout`, see `workflows/AGENTS.md`); the `tools/ui-lint` audit and the `tests/e2e` drivers run only locally.
- `scripts/` and its tests use only the Python standard library and `node:` modules: the `manifest` job runs them without a dependency install. It discovers every `test_*.py`; a new `node --test` file must be added to its command. The same job runs `npm run test:js` (`tests/js`, Node built-ins only).
- Drop an `actionlint.yaml` runner label once the pinned actionlint knows it; every `zizmor.yml` ignore keeps its reason comment.

### Testing Requirements
- Workflow lint, the `scripts/` tests and the local equivalents of every CI step are listed in `workflows/AGENTS.md`.
- Validate `renovate.json` with `npx renovate-config-validator` when it changes.

### Common Patterns
- Workflow conventions (SHA pins, permissions, runners, timeouts, `env:` instead of inline `${{ }}`) are owned by `workflows/AGENTS.md`.

## Dependencies

### Internal
- `docker/Dockerfile`, `docker/entrypoint.sh`, `docker/healthcheck.sh`, `zensical.toml`, `pyproject.toml`, `CHANGELOG.md`, `LICENSE`, `.trivyignore`, `tests/`, `tools/`.

### External
- GitHub Actions, Docker Hub, GitHub Pages, Renovate, Trivy.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
