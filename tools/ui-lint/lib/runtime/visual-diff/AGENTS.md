<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# visual-diff

## Purpose

Screenshot comparison producing diff artifacts.

## Key Files

| File | Description |
|---|---|
| `diff-artifacts.mjs` | `diffScreenshots`, `writeDiffArtifact` |
| `pixelmatch.mjs` | `loadImageBuffer`, `normalizeDimensions`, `computePixelDiff` |

## For AI Agents

### Testing Requirements

- Covered by `tests/runtime/browser-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### External

- `pixelmatch`, `pngjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
