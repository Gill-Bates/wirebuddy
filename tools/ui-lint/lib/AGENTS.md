<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-09-21 -->
# lib

## Purpose

Shared implementation modules for the UI linter: token-driven configuration, design-token parsing, device/browser matrices, runtime (auth, screenshots, telemetry, visual diff), DOM snapshotting, findings policy engine, rule registry orchestration, view planning, and several diagnostics helpers. Many top-level `*.mjs` files are thin compatibility facades over the modular subdirectories.

## Key Files

| File | Description |
|---|---|
| `constants.mjs` | Facade: `export *` from `config/index.mjs` |
| `browser-utils.mjs` | Facade re-exporting the `runtime/` API (login, motion, CLS, screenshots, telemetry, visual diff, browser session) |
| `audit-helpers.mjs` | Facade re-exporting `orchestration/audit-runner.mjs` |
| `dom-snapshot.mjs` | Facade: `export *` from `dom-runtime/index.mjs` |
| `findings.mjs` | Facade exporting `summarizeFindings`, `isExpectedStatusUnavailable` |
| `runtime-config.mjs` | Facade over `runtime-orchestration/` (profiles, run paths, context options) |
| `views.mjs` | Facade over `view-orchestration/` (`VIEWS`, `LOGIN_FAILURE_VIEWS`) |
| `design-tokens.mjs` | Loads/caches design tokens from the app CSS; exports `tokens`, `loadDesignTokens`, `loadDesignTokensAsync`, snapshot helpers |
| `device-matrix.mjs` | Device matrix runtime: `getDevice(s)`, `resolveDeviceMatrix`, `getBreakpointViewports`, built on Playwright device descriptors |
| `rule-registry.mjs` | Public rule registry API (`registerRule`, `runRule`, `runAllRules`, `RuleBuilder`, ...) backed by `rule-orchestration/` |
| `dom-health.mjs` | Correlates console entries with route/component/browser context (`buildDomHealthState`, `correlateConsoleEntries`) |
| `ui-health-score.mjs` | `buildUIHealthReport`: aggregate UI health score/report |
| `ux-severity.mjs` | `classifyUxIssue`, `scoreUxIssues` |
| `interaction-utils.mjs` | Touch-target thresholds, density/importance heuristics, `inspectInteractionTargets`, `groupInteractionViolations` |
| `layout-diagnostics.mjs` | Horizontal-overflow diagnostics: root-cause search, region capture, classification |
| `scroll-diagnostics.mjs` | Scroll-trap diagnostics and classification |
| `focus-flow.mjs` | Tab-order simulation (`simulateTabNavigation`, `snapshotFocusState`) |
| `focus-visibility.mjs` | Focus-indicator contrast/geometry (`computeContrastRatio`, `isFocusVisibleEnough`) |

## Subdirectories

| Directory | Purpose |
|---|---|
| `accessibility/` | axe runner and violation normalisation (see `accessibility/AGENTS.md`) |
| `browsers/` | Browser launcher adapters, capability matrix (see `browsers/AGENTS.md`) |
| `config/` | Token-resolved policy/contract configuration (see `config/AGENTS.md`) |
| `console/` | Console allowlist, filtering, severity (see `console/AGENTS.md`) |
| `design-tokens/exports/` | Serializable token payloads (see `design-tokens/exports/AGENTS.md`) |
| `design-tokens/parser/` | PostCSS token parsing (see `design-tokens/parser/AGENTS.md`) |
| `design-tokens/providers/` | Token providers: css/json/figma (see `design-tokens/providers/AGENTS.md`) |
| `design-tokens/resolver/` | var() chain and unit resolution (see `design-tokens/resolver/AGENTS.md`) |
| `design-tokens/runtime/` | Token runtime, cache, snapshots (see `design-tokens/runtime/AGENTS.md`) |
| `design-tokens/schema/` | Token categories and schema validation (see `design-tokens/schema/AGENTS.md`) |
| `design-tokens/themes/` | Theme overlays and drift diffing (see `design-tokens/themes/AGENTS.md`) |
| `device-runtime/` | Device/browser/network/scenario runtime (see `device-runtime/AGENTS.md`) |
| `dom/` | DOM mutation-stability observer (see `dom/AGENTS.md`) |
| `dom-runtime/` | DOM snapshot engine (see `dom-runtime/AGENTS.md`) |
| `findings/engine/, policies/, scopes/, severity/, explainability/, exports/` | Findings evaluation pipeline (each has its own `AGENTS.md`) |
| `fonts/` | Font loading, FOUT, icon-font checks (see `fonts/AGENTS.md`) |
| `orchestration/` | Extended-audit runner and facade (see `orchestration/AGENTS.md`) |
| `performance/` | Performance metric collectors (see `performance/AGENTS.md`) |
| `rule-orchestration/` | Rule registry engine and planner (see `rule-orchestration/AGENTS.md`) |
| `runtime/` | Browser runtime: auth, browser, motion, observers, screenshots, telemetry, visual-diff (see `runtime/AGENTS.md`) |
| `runtime-orchestration/` | Runtime profiles, context, scheduler (see `runtime-orchestration/AGENTS.md`) |
| `view-orchestration/` | View catalog and coverage planner (see `view-orchestration/AGENTS.md`) |
| `visual/` | SSIM implementation (see `visual/AGENTS.md`) |

## For AI Agents

### Working In This Directory

- `lib/design-tokens/` and `lib/findings/` have no files of their own; only their subdirectories do, so their docs point directly to this file as parent.
- Prefer editing the modular subdirectory and keep the facade re-exports unchanged; `run-ui-lint.mjs`, `rules/` and `tests/` import through the facades.
- Modules named `*-runtime` / `*-orchestration` return frozen or serialisable objects; several functions run inside `page.evaluate` and must stay self-contained (no closures over Node values).

### Testing Requirements

- See per-directory docs; specs live in `tests/` (config, runtime, findings, rules, orchestration, accessibility, ...). Run `cd tools/ui-lint && npm test` after any change to a facade or shared module.

### Common Patterns

- Copyright header comment on every file; `export` names are the public API, re-exported through facades.
- Configuration objects are `Object.freeze`d (`deepFreeze` helper repeated locally in config modules).

## Dependencies

### Internal

- `../rules/` (rules import `rule-registry.mjs` and diagnostics helpers), `/opt/wirebuddy/app/static` CSS (design tokens)

### External

- `playwright`, `@axe-core/playwright`, `postcss`, `pixelmatch`, `pngjs`, `ssim.js`, Node built-ins (`node:fs`, `node:crypto`, `node:path`)

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
