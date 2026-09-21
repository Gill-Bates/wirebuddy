<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# config

## Purpose

Token-driven configuration platform: every threshold and contract used by rules and the entry point is resolved from design tokens with fallbacks, frozen, and exported through `index.mjs` (re-exported as `lib/constants.mjs`).

## Key Files

| File | Description |
|---|---|
| `index.mjs` | Single export surface for all policies, contracts, token helpers and runtime profiles |

## Subdirectories

| Directory | Purpose |
|---|---|
| `accessibility/` | Contrast, focus and touch-target policies (see `accessibility/AGENTS.md`) |
| `components/` | Component contracts (see `components/AGENTS.md`) |
| `layout/` | Layout/overflow/footer policies (see `layout/AGENTS.md`) |
| `motion/` | Motion reset policy (see `motion/AGENTS.md`) |
| `runtime/` | Profiles and evaluate payloads (see `runtime/AGENTS.md`) |
| `screenshots/` | Screenshot timing policy (see `screenshots/AGENTS.md`) |
| `themes/` | Theme registry (see `themes/AGENTS.md`) |
| `tokens/` | Token resolver, schema, validation (see `tokens/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- New constants must be added in the relevant subdirectory and re-exported from `index.mjs`, otherwise `run-ui-lint.mjs` (via `lib/constants.mjs`) cannot see them.

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- Values are read through `resolveOptionalToken` with literal fallbacks; policies are `Object.freeze`d.

## Dependencies

### Internal

- `../design-tokens.mjs`

### External

- None

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
