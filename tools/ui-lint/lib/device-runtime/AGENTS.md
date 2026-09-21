<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# device-runtime

## Purpose

Deterministic device/browser/network/scenario runtime: catalogues of devices, browser engine features, network profiles and scenarios, per-device viewport/DPR/safe-area runtimes, a hashed device matrix and Playwright option adapters.

## Key Files

| File | Description |
|---|---|
| `index.mjs` | Export surface for the device runtime |

## Subdirectories

| Directory | Purpose |
|---|---|
| `browsers/` | Engine feature profiles (see `browsers/AGENTS.md`) |
| `devices/` | Device catalog and matrices (see `devices/AGENTS.md`) |
| `exports/` | Serializable/adapter exports (see `exports/AGENTS.md`) |
| `network/` | Network profiles (see `network/AGENTS.md`) |
| `rendering/` | Viewport/DPR/safe-area runtimes (see `rendering/AGENTS.md`) |
| `runtime/` | Device and matrix runtimes (see `runtime/AGENTS.md`) |
| `scenarios/` | Usage scenarios (see `scenarios/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- `../device-matrix.mjs` builds on this runtime; check it when changing exports.

### Testing Requirements

- Covered by `tests/config/device-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Objects are frozen; runtimes expose `snapshot()` and `hash()`.

## Dependencies

### Internal

- `../device-matrix.mjs`

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
