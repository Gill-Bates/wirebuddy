<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# devices

## Purpose

Device catalog (desktop/tablet/mobile classes) and default/extended matrices.

## Key Files

| File | Description |
|---|---|
| `descriptors.mjs` | `DEVICE_CATALOG`, `DEVICE_CATEGORIES`, `DEFAULT_MATRIX`, `EXTENDED_MATRIX`, `CUSTOM_VIEWPORTS` (~270 lines) |

## For AI Agents

### Working In This Directory

- Adding a device grows the default audit runtime; touch `DEFAULT_MATRIX` deliberately.

### Testing Requirements

- Covered by `tests/config/device-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
