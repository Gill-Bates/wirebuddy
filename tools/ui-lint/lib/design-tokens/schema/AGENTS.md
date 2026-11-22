<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# schema

## Purpose

Token category list and schema, plus validators reporting missing, unknown and unused tokens.

## Key Files

| File | Description |
|---|---|
| `categories.mjs` | `TOKEN_CATEGORIES`, `TOKEN_CATEGORY_LOOKUP` |
| `token-schema.mjs` | `TOKEN_SCHEMA_VERSION`, `TOKEN_SCHEMA` |
| `validation.mjs` | `validateTokens`, `findMissingTokens`, `findUnknownTokens`, `findUnusedTokens` |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
