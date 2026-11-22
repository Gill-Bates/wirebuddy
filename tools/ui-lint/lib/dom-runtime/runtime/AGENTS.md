<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# runtime

## Purpose

Snapshot support: identity, change detection and serialisation.

## Key Files

| File | Description |
|---|---|
| `stable-ids.mjs` | `buildStableId` |
| `mutation-fingerprints.mjs` | `buildMutationFingerprint` |
| `serialization.mjs` | `serializeCompact`, `serializeVerbose` |
| `incremental-snapshots.mjs` | `buildIncrementalSnapshot` |

## For AI Agents

### Testing Requirements

- Covered by `tests/runtime/dom-snapshot.spec.js`. Run `cd tools/ui-lint && npx playwright test <spec>`.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
