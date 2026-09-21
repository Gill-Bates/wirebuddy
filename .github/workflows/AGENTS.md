<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# workflows

## Purpose
GitHub Actions pipelines. `ci.yml` is the PR gate (ruff, pytest, Dockerfile/entrypoint, manifest invariants). `docker-build.yml` builds, smoke-tests, scans and publishes the multi-arch Docker image and creates the GitHub release on version tags. `docs-build.yml` builds the MkDocs site, checks links, deploys to GitHub Pages and scans the resolved docs environment. `ui-audit.yml` runs the Playwright UI audit against a seeded instance and reports without blocking.

## Key Files
| File | Description |
|------|-------------|
| `ci.yml` | "CI", on push/PR to `main` and manual dispatch. Jobs: `python` (the full ruff rule set, **blocking**, then `pytest`), `container` (`bash -n docker/entrypoint.sh`, `docker build --check`), `manifest` (rejects a reintroduced `VERSION`/`requirements.txt`/`docs/requirements-docs.txt`, asserts the version is `X.Y.Z`-shaped, asserts every runtime dependency carries a `==` pin). Installs deps through `tools/pyproject-deps.py`; sets no `WIREBUDDY_SECRET_KEY` on purpose |
| `docker-build.yml` | "Docker Multi-Arch Build", triggered by `v*` tags and manual dispatch. Jobs: `meta` (validate secrets, derive version/tag/build date from `pyproject.toml`, require the tag to be an ancestor of `main`, resolve the rolling toolchain once, probe Docker Hub for `is_newest`), `build` per arch (buildx, smoke test master and node mode, Trivy CRITICAL/HIGH with `.trivyignore`, record toolchain versions and the image digest, push arch image), `create-manifest` (cross-arch version parity gate, digest-based index, `latest` only when `is_newest`, verify the published index), `cleanup-arch-tags` (`if: always()`, removes the fragment tags), `cleanup-dockerhub-tags` (gated on `is_newest`), `create-release`. Trivy action pinned to a commit SHA |
| `docs-build.yml` | "Deploy Documentation", triggered by changes to `docs/**`, `CHANGELOG.md`, `LICENSE`, `pyproject.toml`, `tools/pyproject-deps.py`, the workflow itself, a successful `workflow_run` of the release workflow, weekly cron and manual dispatch. Installs the `docs` extra, copies CHANGELOG/LICENSE into docs, runs `mkdocs build -f docs/mkdocs.yml --strict`, checks links with lychee, deploys to Pages from `main`; the `security-scan` job installs the extra into a venv and runs Trivy against `pip freeze` output |
| `ui-audit.yml` | "UI Audit", manual dispatch (engine choice) and PR to `main`. Seeds an admin with `tools/ci-seed-admin.py`, starts `run.py`, asserts the bootstrap gate is closed, then runs `npm --prefix tools/ui-lint run audit`. `continue-on-error` at job level: it reports, it never blocks. Summarises `ui-lint-summary.json` and uploads the whole output dir |

## For AI Agents

### Working In This Directory
- Version comes from `pyproject.toml` (read with `tomllib`), not a standalone file; keep that in sync with the Dockerfile.
- Keep third-party actions pinned; document why when pinning by SHA.
- Release pipeline is serialized (`concurrency: docker-release`, no cancel); do not change that.
- Docs builds use `--strict`: a broken nav entry or link fails CI.
- Runner images are **named** (`ubuntu-26.04`, `ubuntu-26.04-arm`), never `ubuntu-latest`, so the staged `ubuntu-latest` rollout to 26.04 between 2026-10-19 and 2026-11-19 cannot make two runs of one commit disagree about the OS. Both architectures are on the same generation (26.04 went GA for x64 and arm64 on 2026-09-17); `ubuntu-24.04-arm` is the documented fallback if the arm64 job hits capacity problems.
- `actionlint` is worth running over changes here (`actionlint .github/workflows/*.yml`). `.github/actionlint.yaml` declares the 26.04 labels, because releases before v1.7.8 ship a label list that predates them and would otherwise report every job as an unknown runner.
- `is_newest` is the guard that stops an older tag's re-run from moving `latest` or pruning newer releases. Both are irreversible on Docker Hub — do not weaken it, and keep its Docker Hub tag listing failing closed on any status other than a first-page 404.
- The rolling build inputs (`PYTHON_BASE`, `WIREGUARD_TOOLS_REF`, `APT_CACHE_DATE`) are resolved once in `meta` and passed to both architectures. Resolving them per arch would let the two halves of one manifest ship different toolchains; the parity gate in `create-manifest` is what detects that.
- `ruff check .` is a hard gate and the tree is clean. The deliberate exemptions are in `pyproject.toml`, each with its reasoning: the slowapi `request` parameter (`ARG001` in the router modules), `S603` and `S608` (subprocess invocation of wg/ip/iptables; dynamic SQL identifiers from internal allowlists with bound values), `RUF001-003` (EN DASH in prose), `ASYNC109`, `TRY004`, and local wall-clock scheduling in `app/utils/speedtest_window.py`. `S607` stays enabled on purpose - it is what catches a privileged binary invoked by bare name. `ruff format` is still not a gate.

### Testing Requirements
- Cannot be run locally as workflows; check YAML syntax and rerun via `workflow_dispatch` or a PR.
- The individual steps are reproducible: `ruff check .`, `pytest`, `bash -n docker/entrypoint.sh`, `docker build --check -f docker/Dockerfile .`, `mkdocs build -f docs/mkdocs.yml --strict`.
- For the UI audit: seed a throwaway instance with `tools/ci-seed-admin.py`, then run `tools/ui-lint` against it (see `tools/AGENTS.md`).

### Common Patterns
- Minimal `permissions`, per-job `timeout-minutes`, `needs` chains between jobs, `set -euo pipefail` in shell steps.
- Non-trivial logic (version comparison, manifest verification, arch parity, audit summary) is embedded Python read from a heredoc rather than shell, so it can be extracted and unit-checked.
- `!cancelled()` rather than `success()` where a *skipped* dependency must not suppress a downstream job (see `create-release`).

## Dependencies

### Internal
- `docker/Dockerfile`, `docker/entrypoint.sh`, `docs/mkdocs.yml`, `pyproject.toml`, `.trivyignore`, `CHANGELOG.md`, `tools/pyproject-deps.py`, `tools/ci-seed-admin.py`, `tools/ui-lint/`, `run.py`, `tests/`.

### External
- `actions/checkout`, `actions/setup-python`, `actions/setup-node`, `actions/cache`, `actions/upload-artifact`, `actions/download-artifact`, `docker/setup-buildx-action`, `docker/login-action`, Docker Hub, `aquasecurity/trivy-action`, `lycheeverse/lychee-action`, `actions/upload-pages-artifact`, `actions/deploy-pages`, GitHub Pages, Playwright.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
