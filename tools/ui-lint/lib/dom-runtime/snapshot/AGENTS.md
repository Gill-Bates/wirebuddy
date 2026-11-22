<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# snapshot

## Purpose

Snapshot collection and per-aspect builders.

## Key Files

| File | Description |
|---|---|
| `snapshot-engine.mjs` | `collectDOMSnapshot` (runs in the page incl. shadow DOM), `querySnapshot`, `getByDataUi`, `getByClass`, `getByTag` |
| `layout-snapshot.mjs` | `buildLayoutSnapshot` |
| `rendering-snapshot.mjs` | `buildRenderingSnapshot` |
| `accessibility-snapshot.mjs` | `buildAccessibilitySnapshot` |
| `interaction-snapshot.mjs` | `buildInteractionSnapshot` |

## For AI Agents

### Working In This Directory

- The in-page collector must remain self-contained; do not reference Node-side imports inside it.

### Testing Requirements

- Covered by `tests/runtime/dom-snapshot.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
