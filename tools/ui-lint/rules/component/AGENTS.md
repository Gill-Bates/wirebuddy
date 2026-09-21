<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# component

## Purpose

Component-level rules.

## Key Files

| File | Description |
|---|---|
| `changelog-details.mjs` | About changelog keeps `<details>`/`<summary>` disclosure semantics |
| `dashboard-light-surfaces.mjs` | Dashboard KPI cards use a light surface in the light theme (luminance limit 0.18) |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/component/changelog-details.spec.js`, `tests/component/dashboard-light-surfaces.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Header comment `// Rule: ...`; `meta` object + `registerRule`.

## Dependencies

### Internal

- `../../lib/rule-registry.mjs`
- `../manifest.mjs` (entry required)

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
