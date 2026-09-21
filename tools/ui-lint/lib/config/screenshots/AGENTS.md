<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# screenshots

## Purpose

Screenshot timing: settle times adjusted per browser, device class and CPU profile.

## Key Files

| File | Description |
|---|---|
| `policies.mjs` | `SETTLE_TIME_POLICY`, `SCREENSHOT_TIMING_POLICY`, browser/device/CPU modifiers |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../layout/policies.mjs`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
