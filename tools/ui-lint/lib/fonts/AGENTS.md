<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# fonts

## Purpose

Detects font-loading problems: failed or slow web fonts, flash-of-unstyled-text risk, and broken icon-font glyphs.

## Key Files

| File | Description |
|---|---|
| `font-loading.mjs` | `checkFontLoading(page)` |
| `fout-detection.mjs` | `detectFoutRisk`, `analyzeFoutRisk`, font-family parsing helpers |
| `icon-diagnostics.mjs` | `detectIconFontIssues`, `analyzeIconFontIssues` (checks icons render a visible glyph width) |

## For AI Agents

### Working In This Directory

- Sampling limits are constants (`MAX_TEXT_ELEMENTS`, `MAX_ICON_CHECKS`); keep evaluation bounded on large pages.

### Testing Requirements

- No dedicated spec under `tests/`; it is exercised indirectly through `run-ui-lint.mjs` (via the `orchestration/audit-runner.mjs` facade). Verify with a real audit run against a running WireBuddy (`npm run audit`, needs `UI_LINT_USERNAME`/`UI_LINT_PASSWORD`).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../orchestration/audit-runner.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
