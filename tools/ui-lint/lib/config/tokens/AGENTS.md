<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# tokens

## Purpose

Token access layer for config: schema metadata, path validation, resolution with diagnostics and fallbacks.

## Key Files

| File | Description |
|---|---|
| `resolver.mjs` | `resolveToken`, `resolveRequiredToken`, `resolveOptionalToken`, `hasToken` over `design-tokens.mjs` |
| `schema.mjs` | `TOKEN_SCHEMA`, `TOKEN_SCHEMA_VERSION`, `TOKEN_CATEGORIES`, `isValidTokenCategory` |
| `validation.mjs` | `validateTokenPath` (rejects `__proto__`, `constructor`, `prototype`), `validateAuditConfig`, `validateTokenResolution` |
| `diagnostics.mjs` | `createTokenDiagnostics` |

## For AI Agents

### Working In This Directory

- Keep the reserved-segment check in `validation.mjs`; it guards prototype pollution.

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../../design-tokens.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
