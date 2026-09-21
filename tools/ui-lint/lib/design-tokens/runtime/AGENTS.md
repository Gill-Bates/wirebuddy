<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime

## Purpose

Token runtime that ties providers, resolution, caching and diagnostics together and produces frozen snapshots.

## Key Files

| File | Description |
|---|---|
| `runtime.mjs` | `createTokenRuntime` (~270 lines) |
| `cache.mjs` | `createTokenCache` |
| `snapshots.mjs` | `createTokenSnapshot` (deep-frozen clone) |
| `diagnostics.mjs` | `buildRuntimeDiagnostics` |
| `policies.mjs` | Capability/profile registries and `buildEvaluationPayload`, `buildSerializableConstants` (overlaps `../../config/runtime/policies.mjs`) |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../schema/`, `../themes/theme-diffing.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
