<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
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

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### External

- `postcss`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
