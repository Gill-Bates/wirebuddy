<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# dom-runtime

## Purpose

DOM snapshot engine: collects a deterministic snapshot of the page (layout, rendering, accessibility, interaction, geometry, overlays, scroll topology) that rules consume via `lib/dom-snapshot.mjs`.

## Key Files

| File | Description |
|---|---|
| `index.mjs` | Export surface: `collectDOMSnapshot`, `querySnapshot`, `getByDataUi`, `getByClass`, `getByTag` and all builders |

## Subdirectories

| Directory | Purpose |
|---|---|
| `collections/` | Overlays, scroll topology, semantic groups, virtualised UI (see `collections/AGENTS.md`) |
| `exports/` | Compact/verbose schemas and diffs (see `exports/AGENTS.md`) |
| `geometry/` | Coordinate spaces, clipping, stacking, transforms (see `geometry/AGENTS.md`) |
| `rendering/` | Colors, compositing, paint order, typography (see `rendering/AGENTS.md`) |
| `runtime/` | Stable ids, fingerprints, serialisation, incremental snapshots (see `runtime/AGENTS.md`) |
| `snapshot/` | Snapshot engine and per-aspect builders (see `snapshot/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- Builders are pure functions over snapshot nodes; only `snapshot/snapshot-engine.mjs` touches the live page.

### Testing Requirements

- Covered by `tests/runtime/dom-snapshot.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Node fields consulted include `positioning`, `accessibility.computedRole`, `stableId`, `rect`.

## Dependencies

### Internal

- `../dom-snapshot.mjs` facade

### External

- `playwright` (page handle)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
