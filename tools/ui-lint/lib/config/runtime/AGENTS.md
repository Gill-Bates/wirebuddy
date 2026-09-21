<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# runtime

## Purpose

Runtime profile, device profile and evaluate-payload configuration for browser-side evaluation.

## Key Files

| File | Description |
|---|---|
| `policies.mjs` | `BROWSER_CAPABILITIES`, `MOTION_MODES`, `PAYLOAD_MODES`, `DEVICE_PROFILE_REGISTRY`, `UI_LINT_PROFILES`, `buildEvaluationPayload`, `buildSerializableConstants` |
| `evaluate-payloads.mjs` | `UI_EVAL_CONSTANTS` and wrappers over the policy builders |

## For AI Agents

### Working In This Directory

- Payloads are serialised into `page.evaluate`; keep them JSON-safe.

### Testing Requirements

- Covered by `tests/config/config-platform.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- `../components/`, `../accessibility/`, `../layout/`

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
