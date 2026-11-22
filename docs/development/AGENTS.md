<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# development

## Purpose
Developer-facing documentation: system architecture, local development environment, and contribution rules.

## Key Files
| File | Description |
|------|-------------|
| `architecture.md` | High-level and multi-node architecture, technology stack, application structure with code excerpts, database schema, auth flow, WireGuard/DNS/metrics internals, security, frontend and deployment architecture, performance, design decisions |
| `setup.md` | Prerequisites (Python 3.14), clone, venv and `pip install -e ".[dev]"` including the private `gillbates-*` packages (git plus read access to `Gill-Bates/python-libraries`), configuration, dev database, running, IDE, project tree, workflow, debugging, tests, frontend, building the docs and the Docker image, troubleshooting |
| `contributing.md` | Code of conduct, how to contribute, code style (tabs, `ruff format`, typing, docstrings), testing (including the browser regression suite `tests/layout/`), documentation, git workflow, review, release process, reporting vulnerabilities |

## For AI Agents

### Working In This Directory
- Keep `architecture.md` aligned with the real layout of `app/` (check `app/AGENTS.md`).
- Setup steps must not embed credentials (dev secrets belong in a local `.env`, GitHub access through `gh auth setup-git` or the BuildKit secret `python_libraries_token`).

### Testing Requirements
- Strict Zensical build, see `../AGENTS.md`; commands documented here (`pytest`, `ruff`, `zensical serve`) must actually run.

### Common Patterns
- Long-form guides with fenced Python/shell snippets and directory trees.

## Dependencies

### Internal
- `app/`, `tests/`, `pyproject.toml`, `tools/pyproject-deps.py` (docs requirements), `../features/multi-node.md`.

### External
- pytest, ruff, uvicorn/FastAPI as referenced in the guides; `Gill-Bates/python-libraries` for the `gillbates-*` packages.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
