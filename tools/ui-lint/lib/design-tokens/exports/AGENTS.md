<!-- Parent: ../../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# exports

## Purpose

Serialisable views of a token snapshot for audits and browser injection.

## Key Files

| File | Description |
|---|---|
| `serializable.mjs` | `buildSerializableTokenPayload(snapshot,{category})` (structured clone) |
| `audit-snapshots.mjs` | `buildAuditTokenSnapshot` |
| `browser-payloads.mjs` | `buildBrowserTokenPayload` |

## For AI Agents

### Testing Requirements

- Covered by `tests/config/design-token-runtime.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
