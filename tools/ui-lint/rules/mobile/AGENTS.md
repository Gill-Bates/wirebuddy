<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# mobile

## Purpose

Mobile-specific rules.

## Key Files

| File | Description |
|---|---|
| `scroll-traps.mjs` | Scroll traps and nested scroll containers (iOS/Safari), via `scroll-diagnostics.mjs`; devices: tablet and mobile |

## For AI Agents

### Testing Requirements

- Covered by `tests/mobile/scroll-traps.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../../lib/scroll-diagnostics.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
