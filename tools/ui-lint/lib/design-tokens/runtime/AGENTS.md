<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# runtime

## Purpose

Token runtime that ties providers, resolution, caching and diagnostics together and produces frozen snapshots.

## Key Files

| File | Description |
|---|---|
| `runtime.mjs` | `createTokenRuntime` |
| `cache.mjs` | `createTokenCache` |
| `snapshots.mjs` | `createTokenSnapshot` (deep-frozen clone) |
| `diagnostics.mjs` | `buildRuntimeDiagnostics` |
| `policies.mjs` | Capability/profile registries and `buildEvaluationPayload`, `buildSerializableConstants` (overlaps `../../config/runtime/policies.mjs`) |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../schema/`, `../themes/theme-diffing.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
