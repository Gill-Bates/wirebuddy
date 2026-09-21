<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# parser

## Purpose

Parses the app's CSS with PostCSS into token declarations, a variable index and a dependency graph.

## Key Files

| File | Description |
|---|---|
| `css-parser.mjs` | `parseDesignTokens` (PostCSS parse + normalise) |
| `ast-normalizer.mjs` | `normalizeCssAst` |
| `variable-parser.mjs` | `collectTokenDeclarations`, `buildTokenIndex`, `extractThemeName` (`data-theme` / `data-bs-theme` selectors) |
| `dependency-graph.mjs` | `extractVarReferences`, `buildDependencyGraph`, `detectCircularDependencies` |

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

- `postcss`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
