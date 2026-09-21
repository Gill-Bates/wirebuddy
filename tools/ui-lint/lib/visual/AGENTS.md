<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# visual

## Purpose

Standalone SSIM (structural similarity) image comparison.

## Key Files

| File | Description |
|---|---|
| `ssim.mjs` | `computeSSIM` on PNG data (uses `pngjs`) |

## For AI Agents

### Working In This Directory


### Testing Requirements

- No dedicated spec under `tests/`; it is exercised indirectly through `run-ui-lint.mjs` (via the `orchestration/audit-runner.mjs` facade). Verify with a real audit run against a running WireBuddy (`npm run audit`, needs `UI_LINT_USERNAME`/`UI_LINT_PASSWORD`).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

### External

- `pngjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
