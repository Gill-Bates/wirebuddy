<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
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

### Testing Requirements

- Covered by `tests/runtime/browser-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
