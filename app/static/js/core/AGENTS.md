<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-09-21 | Updated: 2026-11-22 -->
# core

## Purpose
Runtime infrastructure shared by every page controller; loaded from `base.html` before page scripts.

## Key Files
| File | Description |
|------|-------------|
| `dom.js` | `el(tag, {class, id, text, attrs, data, children, on})` builder (text via `textContent`; refuses `on*`, `style`, `srcdoc` and URL attributes whose scheme is not http, https or mailto), `clearChildren()`, `fragment()`; exposed as `window.el` and `window.WB.dom` / `window.WBDom` |
| `flags.js` | `window.WB.flags.url(code)`: flag image URL from `<body data-flag-base-url>` for a validated two-letter code, else `null` |
| `format.js` | `window.WBFormat`: browser-locale/time-zone formatting (`resolved`, `toDate`, `format` with the presets `date`, `time`, `datetime`, `date-short`, `datetime-short`, `time-seconds`, `datetime-seconds`; `number`, `fixed`, `percent`, `compact`, `bytes`, `bandwidth`, `duration`, `relative`; `number`, `fixed`, `compact`, `percent`, `bandwidth` and `duration` return `–` for null, undefined or blank input) and auto-localisation of `<time datetime="…Z" data-wb-format="<preset>">` (`localizeTimes`) and `<span data-wb-number="<kind>" data-wb-value="…">` (`localizeNumbers`); the server only emits UTC (`utc_iso` Jinja filter) and raw numbers |

## For AI Agents
### Working In This Directory
- Changes here affect every page; keep APIs backward compatible. Do not add page-specific logic.
- `el()` `on` handlers are delegated through one capturing `document` listener per event type: the handler gets the node as `this` and as second argument, while `event.currentTarget` is `document`. Use the second argument, not `event.currentTarget`.
- `el()` passes other `attrs` values through unchecked; validate URL-bearing attributes (`href`, `src`, `srcdoc`) at the call site when the value is not a constant.

### Testing Requirements
See `../../AGENTS.md`; `tools/ui-lint/tests/runtime/dom-runtime.spec.js` loads `dom.js` and `format.js`, and `tests/js/format.test.mjs` covers `format.js` per locale and time zone (`npm run test:js`, which runs `node --test "tests/js/*.test.mjs"`). Smoke test several pages.

### Common Patterns
- Global namespace objects, frozen/guarded exports.

## Dependencies
### Internal
- `<body data-flag-base-url>` from `../../../templates/base.html` (read by `flags.js`).
### External
- None.

<!-- MANUAL: Any manually added notes below this line are preserved on regeneration -->
