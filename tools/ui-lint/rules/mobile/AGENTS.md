<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# mobile

## Purpose

Mobile-specific rules.

## Key Files

| File | Description |
|---|---|
| `scroll-traps.mjs` | Scroll traps and nested scroll containers (iOS/Safari), via `scroll-diagnostics.mjs`; devices: tablet and mobile |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/mobile/scroll-traps.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Header comment `// Rule: ...`; `meta` object + `registerRule`.

## Dependencies

### Internal

- `../../lib/scroll-diagnostics.mjs`

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
