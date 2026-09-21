<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# resolver

## Purpose

Resolves raw CSS values to concrete tokens: follows `var()` chains (depth limit 64), evaluates dimension and duration units, computes derived values.

## Key Files

| File | Description |
|---|---|
| `resolve-token.mjs` | `resolveToken` |
| `resolve-var-chain.mjs` | `resolveVarChain` with cycle/depth protection |
| `evaluate-units.mjs` | `evaluateDimension`, `evaluateDuration` |
| `derived-values.mjs` | `deriveTokenValues` (e.g. touch target minimum) |

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
