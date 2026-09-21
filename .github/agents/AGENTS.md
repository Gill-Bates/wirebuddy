<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# agents

## Purpose
Agent prompt files (YAML front matter with name, description, argument-hint, tools, followed by the prompt). Four form a coordinated review suite run in a fixed order; `PythonDev` is a standalone implementation agent. `README.md` is the authoritative description of the suite.

## Key Files
| File | Description |
|------|-------------|
| `README.md` | Review suite overview: ownership matrix, execution order (03 first, then 01/02/04 in parallel, read-only), handover state, write scope, shared policy (trust boundary, execution limits, `TRUSTED_EXECUTION`, severity scale, incidental secrets), report assembly |
| `01_CodeReview.md` | `CodeReview`: read-only senior reviewer (tools read/search/todo) for security, correctness, performance, architecture and production readiness of Python 3.13/FastAPI code; priority tiers, Python/FastAPI/DB/frontend/security rules, output format |
| `02_DRY.agent.md` | `DRY`: read-only analysis of duplicated knowledge (not just code); three-gate workflow, priority scale, good/bad DRY candidates, refactor safety rules, required tests before refactor, finding format |
| `03_CheckComments.md` | `CheckComments`: the only writing agent (tools include edit/execute); auto-fixes comments, docstrings (English only, correctness, tightening), canonical file header, shebang and executable bit without changing logic; has baseline/after verification steps and protected comments |
| `04_CheckIgnoreFiles.md` | `CheckIgnoreFiles`: read-only audit of `.gitignore`, `.dockerignore`, `.trivyignore` and tool ignores for broken semantics, stale rules and build-context leaks; discovery, tool semantics, checks, evidence rules, severity |
| `PythonDev.agent.md` | `PythonDev`: senior Python 3.13 implementation agent (read/edit/search/execute/todo) for FastAPI features and fixes; core principles, stack, security, runtime validation, testing, output and completion rules; not part of the review suite |

## For AI Agents

### Working In This Directory
- Keep front matter fields valid and the `tools` lists consistent with each agent's stated mode (only `03_CheckComments` and `PythonDev` may edit).
- Cross-references between agents and the ownership matrix live in `README.md`; update it whenever ownership, order or shared policy changes.
- Numeric prefixes encode execution order; do not renumber casually.
- Files are prompts, not code: edit wording carefully, avoid contradictory rules, never add secrets.

### Testing Requirements
- None automated; re-read `README.md` to confirm the matrix still matches each prompt after changes.

### Common Patterns
- Shared sections repeated across the suite: Trust boundary, Execution limits, Severity scale, Communication style.

## Dependencies

### Internal
- Reviews target `app/`, `docker/`, `tests/`; ignore audit reads `.gitignore`, `.dockerignore`, `.trivyignore`.

### External
- An agent runtime that understands this front matter (e.g. GitHub Copilot custom agents / VS Code).

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
