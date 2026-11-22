<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# screenshots

## Purpose

Screenshot timing: settle times adjusted per browser, device class and CPU profile.

## Key Files

| File | Description |
|---|---|
| `policies.mjs` | `SETTLE_TIME_POLICY`, `SCREENSHOT_TIMING_POLICY`, browser/device/CPU modifiers |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

## Dependencies

### Internal

- `../layout/policies.mjs`

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
