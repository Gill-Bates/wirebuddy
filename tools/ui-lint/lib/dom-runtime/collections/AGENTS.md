<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# collections

## Purpose

Derived groupings over snapshot nodes.

## Key Files

| File | Description |
|---|---|
| `overlays.mjs` | `buildOverlaySnapshot` (fixed/sticky/dialog) |
| `scroll-topology.mjs` | `buildScrollTopology` (root and nested scrollers) |
| `semantic-groups.mjs` | `buildSemanticGroups` |
| `virtualized-ui.mjs` | `detectVirtualizedUi` |

## For AI Agents

### Testing Requirements

- Covered by `tests/runtime/dom-snapshot.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
