<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# themes

## Purpose

Theme overlays (light, dark inherits light) and detection of token drift between themes.

## Key Files

| File | Description |
|---|---|
| `overlays.mjs` | `THEME_REGISTRY`, `buildThemeOverlay` |
| `theme-diffing.mjs` | `detectTokenDrift` |
| `theme-runtime.mjs` | `createThemeRuntime` |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
