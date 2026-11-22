<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# findings

## Purpose

Spec for findings policies.

## Key Files

| File | Description |
|---|---|
| `layout-policy.spec.js` | Button-height token drift becomes a hard finding; form-switch spacing warning; quiet when no mismatch |

## For AI Agents

### Testing Requirements

- Run `cd tools/ui-lint && npx playwright test tests/findings/`; requires installed Playwright browsers.

## Dependencies

### Internal

- `../../lib/findings.mjs`

### External

- `@playwright/test`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
