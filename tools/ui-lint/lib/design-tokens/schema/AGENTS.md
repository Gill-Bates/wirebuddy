<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# schema

## Purpose

Token category list and schema, plus validators reporting missing, unknown and unused tokens.

## Key Files

| File | Description |
|---|---|
| `categories.mjs` | `TOKEN_CATEGORIES`, `TOKEN_CATEGORY_LOOKUP` |
| `token-schema.mjs` | `TOKEN_SCHEMA_VERSION`, `TOKEN_SCHEMA` |
| `validation.mjs` | `validateTokens`, `findMissingTokens`, `findUnknownTokens`, `findUnusedTokens`, `validateCategory` |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
