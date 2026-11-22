<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# support

## Purpose

Shared fixture module for specs.

## Key Files

| File | Description |
|---|---|
| `contract-fixtures.mjs` | `readRepoFile`, `buildContractStyles(...stylesheetPaths)` (base Bootstrap-like tokens plus repo CSS) and `mountContractPage(page, {width, height, stylesheetPaths, body})`; resolves the repo root four levels up |

## For AI Agents

### Testing Requirements

- Contains no specs; verify changes by running the specs that import it (`accessibility/touch-targets`, `entity-layout`, `mobile`, `overflow`).

## Dependencies

### Internal

- Used by many specs

### External

- Node `fs`, `path`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
