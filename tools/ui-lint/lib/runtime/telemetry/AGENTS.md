<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# telemetry

## Purpose

Buffers for console messages, page errors, requests and responses.

## Key Files

| File | Description |
|---|---|
| `network.mjs` | `createTelemetrySession`, `collectConsoleAndNetwork` |
| `console.mjs` | `createConsoleBuffer` |
| `page-errors.mjs` | `createPageErrorBuffer` |
| `requests.mjs` | `createRequestTimeline` |
| `responses.mjs` | `recordResponse` |

## For AI Agents

### Working In This Directory

- No special constraints beyond the parent directory guidance.

### Testing Requirements

- Covered by `tests/runtime/browser-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>` (no playwright.config file; defaults apply).

### Common Patterns

- No special constraints beyond the parent directory guidance.

## Dependencies

### Internal

- No special constraints beyond the parent directory guidance.

### External

- No special constraints beyond the parent directory guidance.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
