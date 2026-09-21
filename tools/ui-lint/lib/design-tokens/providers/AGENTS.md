<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# providers

## Purpose

Token sources. The CSS provider reads the app stylesheet; JSON and Figma providers are alternative/stub sources.

## Key Files

| File | Description |
|---|---|
| `css-provider.mjs` | `createCssTokenProvider`, `createCssTokenPayload`, `DEFAULT_TOKENS_CSS_PATH`; hashes source with `node:crypto`, supports sync and async load |
| `json-provider.mjs` | `createJsonTokenProvider` for inline tokens |
| `figma-provider.mjs` | `createFigmaTokenProvider` (minimal descriptor) |

## For AI Agents

### Working In This Directory

- Check `DEFAULT_TOKENS_CSS_PATH` if the app's CSS layout changes.

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- Node `fs`, `crypto`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
