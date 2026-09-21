<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime-orchestration

## Purpose

Runtime profile and context orchestration behind `lib/runtime-config.mjs`: resolves profiles (with rationale), builds run output paths, creates a runtime context with policies, state store, scheduler and telemetry, and produces Playwright context options.

## Key Files

| File | Description |
|---|---|
| `runtime-context.mjs` | `resolveRuntimeProfile`, `whyWasThisProfileChosen`, `buildRunPaths`, `createRuntimeContext`, `getBaseContextOptions`, `getAuthenticatedContextOptions`, `getLoginFailureContextOptions` |
| `runtime-profiles.mjs` | `RUNTIME_VERSION`, `RUNTIME_PROFILES`, `listRuntimeProfiles` |
| `runtime-policies.mjs` | `ENVIRONMENTS`, `validateRuntimePolicy`, `buildEnvironmentPolicy` |
| `runtime-scheduler.mjs` | `createRuntimeScheduler` |
| `runtime-state-store.mjs` | `createRuntimeStateStore` |
| `runtime-telemetry.mjs` | `createRuntimeTelemetry`, `buildRuntimeAnalytics` |
| `index.mjs` | Export surface |

## For AI Agents

### Working In This Directory

- `buildRunPaths` rejects absolute screenshot dirs and traversal out of the output dir; keep that guard.

### Testing Requirements

- Covered by `tests/runtime/runtime-config-orchestration.spec.js`, `tests/run-ui-lint.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../runtime-config.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
