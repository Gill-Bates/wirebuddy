//
// tools/ui-lint/run-ui-lint.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium, devices } from 'playwright';

import {
    ABOUT_APPLICATION_DETAILS_FORBIDDEN_ROWS,
    ABOUT_APPLICATION_DETAILS_REQUIRED_ROWS,
    ABOUT_MOBILE_STACK_GAP_VARIANCE_TOLERANCE_PX,
    ABOUT_TOP_ROW_HEIGHT_TOLERANCE_PX,
    ABOUT_UPDATE_TABLE_LABELS,
    BADGE_FONT_SIZE_TOLERANCE_PX,
    BADGE_FONT_WEIGHT_TOLERANCE,
    BADGE_PADDING_TOLERANCE_PX,
    BADGE_RADIUS_TOLERANCE_PX,
    CARD_BORDER_RADIUS_EXPECTED_PX,
    CARD_BORDER_RADIUS_TOLERANCE_PX,
    CLICK_TARGET_MIN_SIZE_PX,
    COMPACT_CARD_ACTION_BORDER_TOP_MAX_PX,
    COMPACT_CARD_ACTION_MARGIN_TOP_MAX_PX,
    COMPACT_CARD_ACTION_PADDING_TOP_MAX_PX,
    COMPONENT_LAYOUT_SHIFT_SETTLE_MS,
    COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX,
    DASHBOARD_TRANSFER_COLOR_DISTANCE_MIN,
    DETAILS_EXPAND_SETTLE_MS,
    FLEX_MIN_HEIGHT_ZERO_TOLERANCE_PX,
    FOOTER_OVERLAP_TOLERANCE_PX,
    FORM_SWITCH_HEIGHT_TOLERANCE_PX,
    FORM_SWITCH_MAX_HEIGHT_PX,
    FULL_MOTION_RESET_CSS,
    GHOST_SCROLL_DELTA_MAX_PX,
    GHOST_SCROLL_MIN_HEIGHT_PX,
    INPUT_GROUP_HEIGHT_EXPECTED_PX,
    INPUT_GROUP_HEIGHT_TOLERANCE_PX,
    KPI_CARD_PADDING_EXPECTED,
    KPI_CARD_PADDING_TOLERANCE,
    KPI_CONTEXTUAL_ICON_CLASSES,
    KPI_ICON_CENTER_TOLERANCE_PX,
    KPI_ICON_NEUTRAL_COLOR_DISTANCE_MAX,
    KPI_ROW_VARIANCE_MAX,
    LOGIN_ERROR_SETTLE_MS,
    LOGIN_LOCKOUT_RESET_MS,
    LOGIN_TEST_STAGGER_MS,
    LOGS_DELETE_HAIRLINE_TOLERANCE_PX,
    MODAL_BACKDROP_ALPHA_EXPECTED,
    MODAL_BACKDROP_ALPHA_TOLERANCE,
    MODAL_BACKDROP_BLUR_EXPECTED_PX,
    MODAL_BACKDROP_BLUR_TOLERANCE_PX,
    MODAL_BACKDROP_SATURATE_EXPECTED,
    MODAL_BACKDROP_SATURATE_TOLERANCE,
    MONOSPACE_PADDING_TOLERANCE_PX,
    MONOSPACE_RADIUS_TOLERANCE_PX,
    OVERFLOW_TOLERANCE_PX,
    SCROLL_EDGE_CLEARANCE_MIN,
    SCREENSHOT_SETTLE_MS,
    SETTINGS_TAB_COLOR_DISTANCE_MAX,
    SLIDER_LABEL_HIDDEN_OPACITY_MAX,
    SLIDER_TICK_ALIGNMENT_TOLERANCE_PX,
    SLIDER_VISIBLE_LABEL_GAP_MIN_PX,
    STACK_GAP_VARIANCE_TOLERANCE_PX,
    STATUS_DETAIL_CARD_TITLES,
    STATUS_FLOW_CONNECTOR_EXPECTATIONS,
    STATUS_FLOW_NODE_EXPECTATIONS,
    TAB_SWITCH_SETTLE_MS,
    UI_EVAL_CONSTANTS,
    VERTICAL_GAP_MAX,
    VERTICAL_GAP_MIN,
    VISUAL_DRIFT_THRESHOLD,
    WCAG_CONTRAST,
} from './lib/constants.mjs';
import {
    captureKpiCards,
    captureStablePair,
    collectConsoleAndNetwork,
    diffScreenshots,
    disableMotion,
    ensureDir,
    installLayoutShiftObserver,
    login,
    applyTheme,
    resetLayoutShiftMetric,
    sanitize,
} from './lib/browser-utils.mjs';
import { summarizeFindings, isExpectedStatusUnavailable } from './lib/findings.mjs';
import { LOGIN_FAILURE_VIEWS, VIEWS } from './lib/views.mjs';

const BASE_URL = process.env.UI_LINT_BASE_URL || 'http://localhost:8000';
const USERNAME = process.env.UI_LINT_USERNAME;
const PASSWORD = process.env.UI_LINT_PASSWORD;

if (!USERNAME || !PASSWORD) {
    console.error('Error: UI_LINT_USERNAME and UI_LINT_PASSWORD environment variables must be set');
    console.error('Example: export UI_LINT_USERNAME=admin && export UI_LINT_PASSWORD=your-password');
    process.exit(1);
}

// Generate unique session ID for this test run to avoid conflicts
const SESSION_ID = Date.now();
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = process.env.UI_LINT_OUTPUT_DIR || `/tmp/wirebuddy-ui-lint-${SESSION_ID}`;
const SCREENSHOT_DIR = path.resolve(
    OUTPUT_DIR,
    process.env.UI_LINT_SCREENSHOT_DIR || 'screenshots'
);
// Results JSON stays in tools/ui-lint/, not in temp
const RESULTS_DIR = SCRIPT_DIR;

async function collectPageMetrics(page, scope) {
    return page.evaluate(async ({ scope, constants }) => {
        const round = (value) => Math.round(value * 10) / 10;
        const norm = (value) => (value || '').replace(/\s+/g, ' ').trim();
        const BREAKPOINT_MIN = {
            base: 0,
            sm: 576,
            md: 768,
            lg: 992,
            xl: 1200,
            xxl: 1400,
        };
        const interactiveSelector = 'button, [role="button"], a[href], input:not([type="hidden"]), select, textarea';
        const clickTargetSelector = [
            'button',
            '.btn',
            '[role="button"]',
            'a[href]',
            'summary',
            'input[type="button"]',
            'input[type="submit"]',
            'input[type="reset"]',
            // Full-size form selects (not -sm variants used in compact toolbars)
            'select.form-select:not(.form-select-sm)',
        ].join(', ');
        const focusableSelector = [
            'a[href]',
            'button',
            'input:not([type="hidden"])',
            'select',
            'textarea',
            'summary',
            '[tabindex]',
        ].join(', ');
        const allowedOverflowSelector = '.leaflet-tile-container, .leaflet-tile, #settingsTabs .nav-item, #settingsTabs .nav-link';
        const badgeConsistencyExcludeSelector = [
            '.wb-onboarding-step-badge',
            '.dns-badge-custom-rule',
            '.custom-chart-legend .badge',
            '.blocklist-hero-meta .badge',
            '.map-popup-header .badge',
            '.badge.small',
            '.badge.rounded-circle',
        ].join(', ');
        const monospaceToneExcludeSelector = [
            'input',
            'textarea',
            'select',
            'button',
            'pre',
            'td',
            'th',
            '.form-control',
            '.otp-digit',
            '#recovery-codes',
            '.peer-last-seen',
            'td[data-label="Last Seen"]',
        ].join(', ');
        const contentRoot = document.querySelector('main.main-content') || document.body;

        const isInsideInactivePane = (el) => {
            const pane = el.closest('.tab-pane');
            return Boolean(pane && !pane.classList.contains('active'));
        };

        const isIntentionallyHidden = (el) => Boolean(
            el.closest('.modal:not(.show)')
            || el.closest('.collapse:not(.show)')
            || el.closest('.navbar-collapse:not(.show)')
            || el.closest('.hidden')
            || el.closest('.d-none')
            || el.closest('[hidden]')
            || el.closest('[aria-hidden="true"]')
            || el.closest('[role="presentation"]')
        );

        const isVisible = (el) => {
            if (!el || !el.isConnected || isInsideInactivePane(el) || isIntentionallyHidden(el)) return false;
            const style = window.getComputedStyle(el);
            if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
            const rect = el.getBoundingClientRect();
            return rect.width > 0 && rect.height > 0;
        };

        const isInContentRoot = (el) => contentRoot === document.body || contentRoot.contains(el);

        const isDisabled = (el) => Boolean(
            el.disabled
            || el.getAttribute('aria-disabled') === 'true'
            || el.getAttribute('disabled') !== null
        );

        const shouldSkipInlineClickTarget = (el) => {
            if (el.tagName !== 'A') return false;
            if (el.classList.contains('btn') || el.getAttribute('role') === 'button') return false;
            // Footer text links are intentionally compact and are not treated as button-like touch targets.
            if (el.classList.contains('wb-footer-link') || el.closest('.wb-footer')) return true;
            return Boolean(el.closest('p, li, td, th, .table, .dropdown-menu, .breadcrumb, .pagination'));
        };

        const shouldSkipCompactControlClickTarget = (el) => {
            if (el.tagName === 'BUTTON' || el.tagName === 'SUMMARY') return true;
            if (el.classList.contains('btn')) return true;
            if (el.matches('.leaflet-control-zoom a, .leaflet-bar a')) return true;
            return false;
        };

        const focusStyleSnapshot = (el) => {
            const style = window.getComputedStyle(el);
            return {
                outlineStyle: style.outlineStyle,
                outlineWidth: Number.parseFloat(style.outlineWidth || '0'),
                outlineColor: normalizeColor(style.outlineColor),
                boxShadow: style.boxShadow,
                borderColor: normalizeColor(style.borderTopColor),
                backgroundColor: normalizeColor(style.backgroundColor),
                color: normalizeColor(style.color),
            };
        };

        const hasVisibleFocusIndicator = (before, after) => {
            const outlineVisible = after.outlineStyle !== 'none' && after.outlineWidth > 0;
            const outlineChanged =
                before.outlineStyle !== after.outlineStyle ||
                Math.abs(before.outlineWidth - after.outlineWidth) > 0.1 ||
                before.outlineColor !== after.outlineColor;
            const boxShadowChanged = before.boxShadow !== after.boxShadow && after.boxShadow !== 'none';
            const borderChanged = before.borderColor !== after.borderColor;
            const backgroundChanged = before.backgroundColor !== after.backgroundColor;
            const colorChanged = before.color !== after.color;

            return (outlineVisible && outlineChanged) || boxShadowChanged || borderChanged || backgroundChanged || colorChanged;
        };

        const rectInfo = (el) => {
            const rect = el.getBoundingClientRect();
            return {
                tag: el.tagName,
                id: el.id || null,
                className: typeof el.className === 'string' ? el.className : null,
                left: round(rect.left),
                right: round(rect.right),
                top: round(rect.top),
                bottom: round(rect.bottom),
                width: round(rect.width),
                height: round(rect.height),
            };
        };

        const getActiveBreakpoint = () => {
            const width = window.innerWidth;
            if (width >= BREAKPOINT_MIN.xxl) return 'xxl';
            if (width >= BREAKPOINT_MIN.xl) return 'xl';
            if (width >= BREAKPOINT_MIN.lg) return 'lg';
            if (width >= BREAKPOINT_MIN.md) return 'md';
            if (width >= BREAKPOINT_MIN.sm) return 'sm';
            return 'base';
        };

        const activeBreakpoint = getActiveBreakpoint();
        const contentElements = Array.from(contentRoot.querySelectorAll('*'));

        const hasBootstrapColClass = (el) => {
            if (!(el instanceof Element)) return false;
            return Array.from(el.classList).some((cls) => /^col(?:-(?:sm|md|lg|xl|xxl))?(?:-(?:auto|\d{1,2}))?$/.test(cls));
        };

        const getActiveColSpan = (el) => {
            if (!(el instanceof Element)) return null;
            const classes = Array.from(el.classList);
            const candidates = [];

            for (const cls of classes) {
                const match = cls.match(/^col(?:-(sm|md|lg|xl|xxl))?-(\d{1,2})$/);
                if (!match) continue;
                const breakpoint = match[1] || 'base';
                const minWidth = BREAKPOINT_MIN[breakpoint] ?? 0;
                if (window.innerWidth >= minWidth) {
                    candidates.push({ minWidth, span: Number.parseInt(match[2], 10), breakpoint });
                }
            }

            if (!candidates.length) return null;
            candidates.sort((a, b) => b.minWidth - a.minWidth);
            return candidates[0].span;
        };

        const getDisplayUtilityMap = (el) => {
            const map = new Map();
            for (const cls of Array.from(el.classList)) {
                const match = cls.match(/^d(?:-(sm|md|lg|xl|xxl))?-(none|inline|inline-block|block|grid|table|table-cell|table-row|flex|inline-flex)$/);
                if (!match) continue;
                const breakpoint = match[1] || 'base';
                const value = match[2];
                if (!map.has(breakpoint)) map.set(breakpoint, new Set());
                map.get(breakpoint).add(value);
            }
            return map;
        };

        const normalizeFontFamily = (value) =>
            String(value || '')
                .toLowerCase()
                .replace(/["']/g, '')
                .replace(/\s+/g, ' ')
                .trim();
        const normalizeColor = (value) =>
            String(value || '')
                .toLowerCase()
                .replace(/\s+/g, '');
        const colorProbe = document.createElement('span');
        colorProbe.setAttribute('aria-hidden', 'true');
        colorProbe.style.position = 'fixed';
        colorProbe.style.left = '-9999px';
        colorProbe.style.top = '0';
        colorProbe.style.pointerEvents = 'none';
        colorProbe.style.visibility = 'hidden';
        document.body.appendChild(colorProbe);
        const parseColor = (raw) => {
            const value = String(raw || '').trim();
            if (!value) return null;

            const parseComputedColor = (computed) => {
                const match = computed.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([0-9.]+))?\)/i);
                if (!match) return null;
                return {
                    r: Number(match[1]),
                    g: Number(match[2]),
                    b: Number(match[3]),
                    a: match[4] == null ? 1 : Number(match[4]),
                };
            };

            const directMatch = parseComputedColor(value);
            if (directMatch) return directMatch;

            colorProbe.style.color = '';
            colorProbe.style.color = value;
            if (!colorProbe.style.color) return null;
            return parseComputedColor(window.getComputedStyle(colorProbe).color || '');
        };
        const parseBackdropFilter = (value) => {
            const raw = String(value || '');
            const blurMatch = raw.match(/blur\(([-\d.]+)px\)/i);
            const saturateMatch = raw.match(/saturate\(([-\d.]+)\)/i);
            return {
                raw,
                blurPx: blurMatch ? Number.parseFloat(blurMatch[1]) : null,
                saturate: saturateMatch ? Number.parseFloat(saturateMatch[1]) : null,
            };
        };

        const duplicateIdsMap = new Map();
        for (const el of document.querySelectorAll('[id]')) {
            duplicateIdsMap.set(el.id, (duplicateIdsMap.get(el.id) || 0) + 1);
        }
        const duplicateIds = Array.from(duplicateIdsMap.entries())
            .filter(([, count]) => count > 1)
            .map(([id, count]) => ({ id, count }));

        const emptyAriaLabels = Array.from(document.querySelectorAll('[aria-label]'))
            .filter((el) => isVisible(el) && !norm(el.getAttribute('aria-label')))
            .map(rectInfo);

        const imgsWithoutAlt = Array.from(document.images)
            .filter((img) => isVisible(img) && !img.hasAttribute('alt'))
            .map((img) => ({ src: img.getAttribute('src'), className: img.className || null }));

        const emptyAltInteractive = Array.from(document.querySelectorAll('a img, button img'))
            .filter((img) => isVisible(img) && norm(img.getAttribute('alt')) === '')
            .map((img) => ({ src: img.getAttribute('src'), parentTag: img.parentElement?.tagName || null }));

        const unlabeledControls = Array.from(document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="reset"]), select, textarea'))
            .filter((el) => {
                if (!isVisible(el) || !isInContentRoot(el) || el.disabled) return false;
                const id = el.id;
                const hasLabelFor = id && document.querySelector(`label[for="${CSS.escape(id)}"]`);
                const wrappedLabel = el.closest('label');
                const ariaLabel = norm(el.getAttribute('aria-label'));
                const ariaLabelledBy = norm(el.getAttribute('aria-labelledby'));
                const title = norm(el.getAttribute('title'));
                return !(hasLabelFor || wrappedLabel || ariaLabel || ariaLabelledBy || title);
            })
            .map((el) => ({ tag: el.tagName, id: el.id || null, type: el.getAttribute('type') || null }));

        const namelessButtons = Array.from(document.querySelectorAll('button, [role="button"]'))
            .filter((el) => {
                if (!isVisible(el) || !isInContentRoot(el)) return false;
                const text = norm(el.textContent);
                const ariaLabel = norm(el.getAttribute('aria-label'));
                const ariaLabelledBy = norm(el.getAttribute('aria-labelledby'));
                const title = norm(el.getAttribute('title'));
                return !(text || ariaLabel || ariaLabelledBy || title);
            })
            .map(rectInfo);

        const clickTargetsTooSmall = Array.from(contentRoot.querySelectorAll(clickTargetSelector))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !isDisabled(el))
            .filter((el) => !shouldSkipInlineClickTarget(el))
            .filter((el) => !shouldSkipCompactControlClickTarget(el))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                return rect.width < constants.CLICK_TARGET_MIN_SIZE_PX || rect.height < constants.CLICK_TARGET_MIN_SIZE_PX;
            })
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                text: norm(el.textContent).slice(0, 60) || null,
            }));

        // Icon buttons: icons inside buttons must have pointer-events: none
        // to ensure touch events pass through to the button (mobile touch fix)
        const iconButtonsTouchBlocked = Array.from(contentRoot.querySelectorAll('button .material-icons, [role="button"] .material-icons'))
            .filter((icon) => {
                if (!isVisible(icon)) return false;
                const btn = icon.closest('button, [role="button"]');
                if (!btn || !isInContentRoot(btn)) return false;
                const style = window.getComputedStyle(icon);
                return style.pointerEvents !== 'none';
            })
            .slice(0, 20)
            .map((icon) => {
                const btn = icon.closest('button, [role="button"]');
                return {
                    ...rectInfo(btn),
                    iconText: icon.textContent?.trim() || null,
                    pointerEvents: window.getComputedStyle(icon).pointerEvents,
                };
            });

        // Deprecated button classes check (exclude input-group buttons where btn-icon is valid)
        const deprecatedButtonClasses = Array.from(contentRoot.querySelectorAll('.btn-icon, button.btn-icon, [role="button"].btn-icon'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => !el.closest('.input-group')) // btn-icon is valid inside input-groups
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                text: norm(el.textContent).slice(0, 60) || null,
                deprecatedClass: 'btn-icon',
                replacement: 'Use btn-outline-* with icon-md class instead of btn-icon',
            }));

        const focusableElements = Array.from(contentRoot.querySelectorAll(focusableSelector))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !isDisabled(el))
            .filter((el) => !el.closest('.leaflet-control-container'))
            .filter((el) => el.tabIndex >= 0);

        const focusOrderIssues = [];
        for (let index = 1; index < focusableElements.length; index += 1) {
            const previous = focusableElements[index - 1];
            const current = focusableElements[index];
            const prevRect = previous.getBoundingClientRect();
            const currRect = current.getBoundingClientRect();

            if (currRect.top + 4 < prevRect.top) {
                focusOrderIssues.push({
                    previous: rectInfo(previous),
                    current: rectInfo(current),
                });
            }
        }

        const focusIndicatorMissing = [];
        const focusSample = focusableElements.slice(0, 20);
        const priorFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        for (const el of focusSample) {
            const before = focusStyleSnapshot(el);
            try {
                el.focus({ preventScroll: true });
            } catch {
                continue;
            }

            const after = focusStyleSnapshot(el);
            if (document.activeElement === el && !hasVisibleFocusIndicator(before, after)) {
                focusIndicatorMissing.push({
                    ...rectInfo(el),
                    text: norm(el.textContent).slice(0, 60) || null,
                });
            }
        }
        if (priorFocused && typeof priorFocused.focus === 'function') {
            priorFocused.focus({ preventScroll: true });
        } else if (document.activeElement instanceof HTMLElement) {
            document.activeElement.blur();
        }

        const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6'))
            .filter((el) => isVisible(el))
            .map((el) => ({ tag: el.tagName, level: Number(el.tagName.slice(1)), text: norm(el.textContent).slice(0, 120) }));
        const headingSkips = [];
        for (let index = 1; index < headings.length; index += 1) {
            const prev = headings[index - 1];
            const current = headings[index];
            if (current.level - prev.level > 1) {
                headingSkips.push({ from: prev.tag, to: current.tag, text: current.text });
            }
        }

        const tablesWithoutHeaders = Array.from(document.querySelectorAll('table'))
            .filter((table) => isVisible(table) && isInContentRoot(table) && !table.querySelector('th'))
            .map(rectInfo);

        // =============================================================================
        // Table Cell Overlap Detection
        // Detects horizontal overlap between adjacent table cells (e.g. badges overlapping action buttons)
        // =============================================================================
        const tableCellOverlapIssues = Array.from(document.querySelectorAll('table'))
            .filter((table) => isVisible(table) && isInContentRoot(table))
            .flatMap((table) => {
                const rows = Array.from(table.querySelectorAll('tbody tr'));
                return rows.map((row) => {
                    const cells = Array.from(row.children).filter((c) => c instanceof HTMLElement);
                    if (cells.length < 2) return null;

                    const overlaps = [];

                    for (let i = 0; i < cells.length - 1; i++) {
                        const a = cells[i];
                        const b = cells[i + 1];

                        if (!isVisible(a) || !isVisible(b)) continue;

                        const rectA = a.getBoundingClientRect();
                        const rectB = b.getBoundingClientRect();

                        // Detect horizontal overlap (with small tolerance)
                        if (rectA.right > rectB.left + 1) {
                            overlaps.push({
                                leftCell: {
                                    index: i,
                                    ...rectInfo(a),
                                },
                                rightCell: {
                                    index: i + 1,
                                    ...rectInfo(b),
                                },
                                overlapPx: round(rectA.right - rectB.left),
                            });
                        }
                    }

                    if (!overlaps.length) return null;

                    return {
                        table: rectInfo(table),
                        row: rectInfo(row),
                        overlaps,
                    };
                }).filter(Boolean);
            }).slice(0, 20);

        // Detect tables overflowing containers without responsive wrapper
        const tablesWithoutResponsive = Array.from(document.querySelectorAll('table'))
            .filter((table) => {
                if (!isVisible(table) || !isInContentRoot(table)) return false;
                const rect = table.getBoundingClientRect();
                const parentRect = table.parentElement?.getBoundingClientRect();
                return (
                    parentRect &&
                    rect.width > parentRect.width + 2 &&
                    !table.closest('.table-responsive')
                );
            });

        // Ghost scroll detection (tablet common issue)
        const doc = document.documentElement;
        const ghostScroll = doc.scrollHeight > window.innerHeight &&
            contentElements.some((el) => {
                const style = window.getComputedStyle(el);
                return (
                    isVisible(el) &&
                    (style.overflowY === 'auto' || style.overflowY === 'scroll') &&
                    el.scrollHeight > el.clientHeight
                );
            });

        const horizontalOverflow = {
            hasOverflow: doc.scrollWidth > window.innerWidth + constants.OVERFLOW_TOLERANCE_PX,
            scrollWidth: doc.scrollWidth,
            viewportWidth: window.innerWidth,
            contentRight: round(contentRoot.getBoundingClientRect().right),
            contentLeft: round(contentRoot.getBoundingClientRect().left),
            offenders: Array.from(document.querySelectorAll('body *'))
                .filter((el) => isVisible(el) && isInContentRoot(el) && !el.matches(allowedOverflowSelector))
                .filter((el) => {
                    const rootRect = contentRoot.getBoundingClientRect();
                    const rect = el.getBoundingClientRect();
                    return rect.right - rootRect.right > 2 || rect.left < rootRect.left - 2;
                })
                .slice(0, 20)
                .map(rectInfo),
        };

        const clippedButtons = Array.from(document.querySelectorAll('button, .btn, [role="button"]'))
            .filter((el) => isVisible(el) && isInContentRoot(el) && !el.closest('#settingsTabs'))
            .filter((el) => !el.matches('.blocklist-source-info') && !el.closest('.input-group'))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                const intersectsViewport = rect.bottom > 0 && rect.top < window.innerHeight && rect.right > 0 && rect.left < window.innerWidth;
                if (!intersectsViewport) return false;
                const insetX = Math.max(6, Math.min(10, rect.width * 0.2));
                const insetY = Math.max(6, Math.min(10, rect.height * 0.2));
                const samplePoints = [
                    [rect.left + rect.width / 2, rect.top + rect.height / 2],
                    [rect.left + insetX, rect.top + insetY],
                    [rect.right - insetX, rect.top + insetY],
                    [rect.left + insetX, rect.bottom - insetY],
                    [rect.right - insetX, rect.bottom - insetY],
                ];
                const occluded = samplePoints.some(([x, y]) => {
                    if (x < 0 || y < 0 || x >= window.innerWidth || y >= window.innerHeight) {
                        return true;
                    }
                    const topEl = document.elementFromPoint(x, y);
                    // Filter out known overlay elements (tooltips, dropdowns, sticky headers)
                    if (topEl && topEl.closest('[role="tooltip"], .tooltip, .popover, .dropdown-menu, .sticky-top, .modal')) {
                        return false;
                    }
                    return Boolean(topEl && topEl !== el && !el.contains(topEl) && !topEl.contains(el));
                });
                return occluded;
            })
            .map(rectInfo);

        const hiddenInteractiveElements = Array.from(contentRoot.querySelectorAll(interactiveSelector))
            .filter((el) => {
                if (el.disabled || isInsideInactivePane(el) || isIntentionallyHidden(el)) return false;
                const style = window.getComputedStyle(el);
                const rect = el.getBoundingClientRect();
                return style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || rect.width === 0 || rect.height === 0;
            })
            .slice(0, 20)
            .map((el) => ({
                tag: el.tagName,
                id: el.id || null,
                className: typeof el.className === 'string' ? el.className : null,
            }));

        const bootstrapGridIssues = Array.from(contentRoot.querySelectorAll('.row'))
            .filter((row) => row instanceof HTMLElement && isInContentRoot(row) && !isIntentionallyHidden(row))
            .map((row) => {
                const children = Array.from(row.children)
                    .filter((child) => child instanceof HTMLElement)
                    .filter((child) => !child.matches('script, style, template'));
                const visibleChildren = children.filter((child) => isVisible(child));
                if (!children.length || !visibleChildren.length) return null;

                const nonColumnChildren = visibleChildren.filter((child) => !hasBootstrapColClass(child));
                const spans = visibleChildren
                    .map((child) => getActiveColSpan(child))
                    .filter((span) => Number.isFinite(span));
                const fixedSpanTotal = spans.reduce((sum, span) => sum + span, 0);
                const issues = [];

                if (!visibleChildren.some((child) => hasBootstrapColClass(child))) {
                    issues.push('rowWithoutColumns');
                }
                if (nonColumnChildren.length) {
                    issues.push('nonColumnDirectChildren');
                }
                if (fixedSpanTotal > 12) {
                    issues.push('columnSpanOverflow');
                }

                if (!issues.length) return null;

                return {
                    ...rectInfo(row),
                    issues,
                    activeBreakpoint,
                    fixedSpanTotal,
                    visibleChildCount: visibleChildren.length,
                    nonColumnChildren: nonColumnChildren.length,
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const bootstrapColumnsOutsideRows = contentElements
            .filter((el) => el instanceof HTMLElement && isVisible(el) && isInContentRoot(el))
            .filter((el) => hasBootstrapColClass(el))
            .filter((el) => !el.closest('.row'))
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                activeBreakpoint,
            }));

        const breakpointDisplayConflicts = Array.from(contentRoot.querySelectorAll('[class]'))
            .filter((el) => el instanceof HTMLElement && isInContentRoot(el) && !isIntentionallyHidden(el))
            .map((el) => {
                const displayMap = getDisplayUtilityMap(el);
                const conflicts = Array.from(displayMap.entries())
                    .filter(([, values]) => values.size > 1)
                    .map(([breakpoint, values]) => ({ breakpoint, values: Array.from(values) }));

                if (!conflicts.length) return null;

                return {
                    ...rectInfo(el),
                    conflicts,
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const navbarCollapseIssues = (() => {
            const issues = [];
            const collapses = Array.from(document.querySelectorAll('.navbar-collapse'));
            const togglers = Array.from(document.querySelectorAll('.navbar-toggler'));

            if (!collapses.length) return issues;

            if (!togglers.length) {
                issues.push({ type: 'missingNavbarToggler', collapseCount: collapses.length });
            }

            for (const collapse of collapses) {
                if (!collapse.classList.contains('collapse')) {
                    issues.push({ type: 'navbarCollapseMissingCollapseClass', element: rectInfo(collapse) });
                }
            }

            for (const toggler of togglers) {
                const target = toggler.getAttribute('data-bs-target') || (toggler.getAttribute('aria-controls') ? `#${toggler.getAttribute('aria-controls')}` : null);
                if (!target) {
                    issues.push({ type: 'navbarTogglerMissingTarget', element: rectInfo(toggler) });
                    continue;
                }

                const targetEl = document.querySelector(target);
                if (!targetEl) {
                    issues.push({ type: 'navbarTogglerTargetMissing', target, element: rectInfo(toggler) });
                }
            }

            if (window.matchMedia('(max-width: 991.98px)').matches) {
                const visibleUncollapsed = collapses
                    .filter((collapse) => isVisible(collapse) && !collapse.classList.contains('show'))
                    .map((collapse) => ({ type: 'navbarCollapseVisibleWithoutShow', element: rectInfo(collapse) }));
                issues.push(...visibleUncollapsed);
            }

            return issues.slice(0, 20);
        })();

        const scrollEdgeCrowding = Array.from(contentRoot.querySelectorAll('.top-domain-scroll-area .top-domain-percent'))
            .filter((el) => isVisible(el))
            .map((el) => {
                const scrollContainer = el.closest('.top-domain-scroll-area');
                if (!scrollContainer || !isVisible(scrollContainer)) return null;

                const badgeRect = el.getBoundingClientRect();
                const containerRect = scrollContainer.getBoundingClientRect();
                const clearance = round(containerRect.right - badgeRect.right);

                if (clearance >= constants.SCROLL_EDGE_CLEARANCE_MIN) return null;

                return {
                    clearance,
                    badge: rectInfo(el),
                    container: rectInfo(scrollContainer),
                };
            })
            .filter(Boolean);

        const isScrollContainer = (el) => {
            if (!el || !isVisible(el) || !isInContentRoot(el)) return false;
            const style = window.getComputedStyle(el);
            return style.overflowY === 'auto' || style.overflowY === 'scroll';
        };

        const resolveTrailingVisibleContent = (container) => {
            let current = container;
            let lastVisibleChild = null;
            let depth = 0;

            while (current && depth < 6) {
                const children = Array.from(current.children)
                    .filter((child) => isVisible(child));

                if (!children.length) break;

                lastVisibleChild = children[children.length - 1];
                if (children.length !== 1) break;

                current = lastVisibleChild;
                depth += 1;
            }

            return {
                lastVisibleChild,
                depth,
            };
        };

        // Generic scroll-bottom clearance check.
        const scrollBottomCrowding = contentElements
            .filter((el) => isScrollContainer(el))
            .map((container) => {
                const { lastVisibleChild, depth } = resolveTrailingVisibleContent(container);
                if (!lastVisibleChild) return null;

                const containerRect = container.getBoundingClientRect();
                const childRect = lastVisibleChild.getBoundingClientRect();
                const clearance = round(containerRect.bottom - childRect.bottom);

                if (clearance >= constants.SCROLL_EDGE_CLEARANCE_MIN) return null;

                return {
                    clearance,
                    traversalDepth: depth,
                    container: rectInfo(container),
                    lastChild: rectInfo(lastVisibleChild),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        // Detect ghost scroll containers (scrollbar visible but minimal overflow 1-8px)
        // Catches layout issues like thead + padding causing tiny overflow
        const ghostScrollContainers = contentElements
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => {
                const style = window.getComputedStyle(el);
                const overflowY = style.overflowY;
                if (overflowY !== 'auto' && overflowY !== 'scroll') return false;

                const delta = el.scrollHeight - el.clientHeight;
                // Real scroll (delta > threshold) is legitimate
                if (delta <= 0) return false;
                if (delta > constants.GHOST_SCROLL_DELTA_MAX_PX) return false;
                // Skip very small containers
                if (el.clientHeight < constants.GHOST_SCROLL_MIN_HEIGHT_PX) return false;

                return true;
            })
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                scrollHeight: el.scrollHeight,
                clientHeight: el.clientHeight,
                delta: el.scrollHeight - el.clientHeight,
                overflowY: window.getComputedStyle(el).overflowY,
            }));

        // Detect scroll-in-scroll and direct .card > scroll-container patterns.
        const nestedScrollContainers = contentElements
            .filter((el) => isScrollContainer(el))
            .filter((el) => el.dataset.uiLintAllow !== 'nested-scroll')
            .map((container) => {
                let parentScroll = null;
                let ancestor = container.parentElement;
                while (ancestor && ancestor !== contentRoot.parentElement) {
                    if (isScrollContainer(ancestor)) {
                        parentScroll = ancestor;
                        break;
                    }
                    ancestor = ancestor.parentElement;
                }

                const directCardParent = container.parentElement?.classList?.contains('card') || false;
                if (!parentScroll && !directCardParent) return null;

                return {
                    container: rectInfo(container),
                    parent: parentScroll ? rectInfo(parentScroll) : null,
                    directCardParent,
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        // =============================================================================
        // Flex Scroll Trap Detection
        // Detects flex children with overflow that cannot scroll due to missing min-height: 0
        // =============================================================================
        const flexScrollTraps = contentElements
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => {
                const style = window.getComputedStyle(el);
                const parent = el.parentElement;
                if (!parent) return false;

                const parentStyle = window.getComputedStyle(parent);

                // Must be flex child
                const isFlexChild =
                    parentStyle.display.includes('flex');

                if (!isFlexChild) return false;

                // Must be scroll container
                const hasScrollableOverflow =
                    style.overflowY === 'auto' || style.overflowY === 'scroll';

                if (!hasScrollableOverflow) return false;

                // Has actual overflow
                const hasOverflow = el.scrollHeight > el.clientHeight + 2;
                if (!hasOverflow) return false;

                // Check min-height issue
                const minHeight = style.minHeight;
                const hasMinHeightZero =
                    minHeight === '0px' || minHeight === '0';

                return !hasMinHeightZero;
            })
            .slice(0, 20)
            .map((el) => {
                const style = window.getComputedStyle(el);
                const parent = el.parentElement;
                const parentStyle = parent ? window.getComputedStyle(parent) : null;

                return {
                    ...rectInfo(el),
                    overflowY: style.overflowY,
                    scrollHeight: el.scrollHeight,
                    clientHeight: el.clientHeight,
                    minHeight: style.minHeight,
                    parentDisplay: parentStyle?.display || null,
                    issue: 'flex-child-missing-min-height-0',
                    recommendation: 'Add min-height: 0 to enable scrolling inside flex container',
                };
            });

        // =============================================================================
        // Double Scroll Detection (page scroll + inner scroll containers)
        // iOS UX anti-pattern: competing scroll contexts confuse users
        // =============================================================================
        const pageScrollable =
            doc.scrollHeight > window.innerHeight + constants.OVERFLOW_TOLERANCE_PX;

        const innerScrollContainers = contentElements
            .filter((el) => {
                if (!isVisible(el) || !isInContentRoot(el)) return false;
                const style = window.getComputedStyle(el);
                const hasScroll =
                    (style.overflowY === 'auto' || style.overflowY === 'scroll') &&
                    el.scrollHeight > el.clientHeight + 2;

                // Ignore tiny or intentional scroll areas
                if (!hasScroll) return false;
                if (el.clientHeight < constants.GHOST_SCROLL_MIN_HEIGHT_PX) return false;

                return true;
            })
            .slice(0, 20)
            .map((el) => ({
                ...rectInfo(el),
                scrollHeight: el.scrollHeight,
                clientHeight: el.clientHeight,
                overflowY: window.getComputedStyle(el).overflowY,
            }));

        const doubleScrollRisk = pageScrollable && innerScrollContainers.length > 0
            ? {
                pageScrollable,
                innerScrollCount: innerScrollContainers.length,
                containers: innerScrollContainers,
            }
            : null;

        const referenceBadge = document.createElement('span');
        referenceBadge.className = 'badge bg-secondary';
        referenceBadge.textContent = 'Reference';
        referenceBadge.setAttribute('aria-hidden', 'true');
        referenceBadge.style.position = 'fixed';
        referenceBadge.style.left = '-9999px';
        referenceBadge.style.top = '0';
        referenceBadge.style.pointerEvents = 'none';
        referenceBadge.style.visibility = 'hidden';
        document.body.appendChild(referenceBadge);

        const referenceBadgeStyle = window.getComputedStyle(referenceBadge);
        const badgeReference = {
            fontFamily: normalizeFontFamily(referenceBadgeStyle.fontFamily),
            fontSize: Number.parseFloat(referenceBadgeStyle.fontSize || '0'),
            fontWeight: Number.parseInt(referenceBadgeStyle.fontWeight || '400', 10),
            borderRadius: Number.parseFloat(referenceBadgeStyle.borderTopLeftRadius || '0'),
            paddingTop: Number.parseFloat(referenceBadgeStyle.paddingTop || '0'),
            paddingRight: Number.parseFloat(referenceBadgeStyle.paddingRight || '0'),
            paddingBottom: Number.parseFloat(referenceBadgeStyle.paddingBottom || '0'),
            paddingLeft: Number.parseFloat(referenceBadgeStyle.paddingLeft || '0'),
        };
        referenceBadge.remove();

        const badgeStyleMismatches = Array.from(contentRoot.querySelectorAll('.badge'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => !el.matches(badgeConsistencyExcludeSelector))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const reasons = [];
                const normalizedFontFamily = normalizeFontFamily(style.fontFamily);
                const fontSize = Number.parseFloat(style.fontSize || '0');
                const fontWeight = Number.parseInt(style.fontWeight || '400', 10);
                const borderRadius = Number.parseFloat(style.borderTopLeftRadius || '0');
                const paddingTop = Number.parseFloat(style.paddingTop || '0');
                const paddingRight = Number.parseFloat(style.paddingRight || '0');
                const paddingBottom = Number.parseFloat(style.paddingBottom || '0');
                const paddingLeft = Number.parseFloat(style.paddingLeft || '0');

                if (normalizedFontFamily !== badgeReference.fontFamily) {
                    reasons.push('fontFamily');
                }
                if (Math.abs(fontSize - badgeReference.fontSize) > constants.BADGE_FONT_SIZE_TOLERANCE_PX) {
                    reasons.push('fontSize');
                }
                if (Math.abs(fontWeight - badgeReference.fontWeight) > constants.BADGE_FONT_WEIGHT_TOLERANCE) {
                    reasons.push('fontWeight');
                }
                if (Math.abs(borderRadius - badgeReference.borderRadius) > constants.BADGE_RADIUS_TOLERANCE_PX) {
                    reasons.push('borderRadius');
                }
                if (
                    Math.abs(paddingTop - badgeReference.paddingTop) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingRight - badgeReference.paddingRight) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingBottom - badgeReference.paddingBottom) > constants.BADGE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingLeft - badgeReference.paddingLeft) > constants.BADGE_PADDING_TOLERANCE_PX
                ) {
                    reasons.push('padding');
                }

                if (!reasons.length) return null;

                return {
                    reasons,
                    text: norm(el.textContent).slice(0, 60),
                    className: typeof el.className === 'string' ? el.className : null,
                    fontFamily: normalizedFontFamily,
                    fontSize: round(fontSize),
                    fontWeight,
                    borderRadius: round(borderRadius),
                    paddingTop: round(paddingTop),
                    paddingRight: round(paddingRight),
                    paddingBottom: round(paddingBottom),
                    paddingLeft: round(paddingLeft),
                    reference: {
                        ...badgeReference,
                        fontSize: round(badgeReference.fontSize),
                        borderRadius: round(badgeReference.borderRadius),
                        paddingTop: round(badgeReference.paddingTop),
                        paddingRight: round(badgeReference.paddingRight),
                        paddingBottom: round(badgeReference.paddingBottom),
                        paddingLeft: round(badgeReference.paddingLeft),
                    },
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const referenceMonospace = document.createElement('span');
        referenceMonospace.className = 'wb-monospace-value font-monospace';
        referenceMonospace.textContent = 'Reference';
        referenceMonospace.setAttribute('aria-hidden', 'true');
        referenceMonospace.style.position = 'fixed';
        referenceMonospace.style.left = '-9999px';
        referenceMonospace.style.top = '0';
        referenceMonospace.style.pointerEvents = 'none';
        referenceMonospace.style.visibility = 'hidden';
        document.body.appendChild(referenceMonospace);

        const referenceMonospaceStyle = window.getComputedStyle(referenceMonospace);
        const monospaceReference = {
            color: normalizeColor(referenceMonospaceStyle.color),
            backgroundColor: normalizeColor(referenceMonospaceStyle.backgroundColor),
            borderRadius: Number.parseFloat(referenceMonospaceStyle.borderTopLeftRadius || '0'),
            paddingTop: Number.parseFloat(referenceMonospaceStyle.paddingTop || '0'),
            paddingRight: Number.parseFloat(referenceMonospaceStyle.paddingRight || '0'),
            paddingBottom: Number.parseFloat(referenceMonospaceStyle.paddingBottom || '0'),
            paddingLeft: Number.parseFloat(referenceMonospaceStyle.paddingLeft || '0'),
        };
        referenceMonospace.remove();

        const monospaceToneMismatches = Array.from(contentRoot.querySelectorAll('code, kbd, samp, .wb-monospace-value, .font-monospace, .asn-badge, .asn-inline, .blocklist-meta-mono'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => !el.matches(monospaceToneExcludeSelector) && !el.closest(monospaceToneExcludeSelector))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const color = normalizeColor(style.color);
                const backgroundColor = normalizeColor(style.backgroundColor);
                const borderRadius = Number.parseFloat(style.borderTopLeftRadius || '0');
                const paddingTop = Number.parseFloat(style.paddingTop || '0');
                const paddingRight = Number.parseFloat(style.paddingRight || '0');
                const paddingBottom = Number.parseFloat(style.paddingBottom || '0');
                const paddingLeft = Number.parseFloat(style.paddingLeft || '0');
                const reasons = [];

                if (color !== monospaceReference.color) reasons.push('color');
                if (backgroundColor !== monospaceReference.backgroundColor) reasons.push('backgroundColor');
                if (Math.abs(borderRadius - monospaceReference.borderRadius) > constants.MONOSPACE_RADIUS_TOLERANCE_PX) reasons.push('borderRadius');
                if (
                    Math.abs(paddingTop - monospaceReference.paddingTop) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingRight - monospaceReference.paddingRight) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingBottom - monospaceReference.paddingBottom) > constants.MONOSPACE_PADDING_TOLERANCE_PX ||
                    Math.abs(paddingLeft - monospaceReference.paddingLeft) > constants.MONOSPACE_PADDING_TOLERANCE_PX
                ) reasons.push('padding');

                if (!reasons.length) return null;

                return {
                    tag: el.tagName,
                    id: el.id || null,
                    className: typeof el.className === 'string' ? el.className : null,
                    text: norm(el.textContent).slice(0, 60),
                    reasons,
                    color,
                    backgroundColor,
                    borderRadius: round(borderRadius),
                    paddingTop: round(paddingTop),
                    paddingRight: round(paddingRight),
                    paddingBottom: round(paddingBottom),
                    paddingLeft: round(paddingLeft),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const colorDistance = (c1, c2) => {
            if (!c1 || !c2) return null;
            return Math.sqrt(
                Math.pow(c1.r - c2.r, 2) +
                Math.pow(c1.g - c2.g, 2) +
                Math.pow(c1.b - c2.b, 2)
            );
        };
        const modalBackdropProbe = document.createElement('div');
        modalBackdropProbe.className = 'modal-backdrop show';
        modalBackdropProbe.setAttribute('aria-hidden', 'true');
        modalBackdropProbe.style.position = 'fixed';
        modalBackdropProbe.style.left = '-9999px';
        modalBackdropProbe.style.top = '0';
        modalBackdropProbe.style.pointerEvents = 'none';
        modalBackdropProbe.style.opacity = '1';
        document.body.appendChild(modalBackdropProbe);

        const modalBackdropStyle = window.getComputedStyle(modalBackdropProbe);
        const modalBackdropFilter = parseBackdropFilter(
            modalBackdropStyle.backdropFilter || modalBackdropStyle.webkitBackdropFilter || ''
        );
        const modalBackdropColor = parseColor(modalBackdropStyle.backgroundColor || '');
        const modalBackdrop = {
            backgroundColor: normalizeColor(modalBackdropStyle.backgroundColor),
            alpha: modalBackdropColor?.a ?? null,
            blurPx: modalBackdropFilter.blurPx,
            saturate: modalBackdropFilter.saturate,
            filterRaw: modalBackdropFilter.raw,
            blurMatchesReference: modalBackdropFilter.blurPx !== null &&
                Math.abs(modalBackdropFilter.blurPx - constants.MODAL_BACKDROP_BLUR_EXPECTED_PX) <= constants.MODAL_BACKDROP_BLUR_TOLERANCE_PX,
            saturateMatchesReference: modalBackdropFilter.saturate !== null &&
                Math.abs(modalBackdropFilter.saturate - constants.MODAL_BACKDROP_SATURATE_EXPECTED) <= constants.MODAL_BACKDROP_SATURATE_TOLERANCE,
            alphaMatchesReference: modalBackdropColor?.a != null &&
                Math.abs(modalBackdropColor.a - constants.MODAL_BACKDROP_ALPHA_EXPECTED) <= constants.MODAL_BACKDROP_ALPHA_TOLERANCE,
        };
        modalBackdropProbe.remove();

        const toLuminance = (channel) => {
            const value = channel / 255;
            return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
        };
        const contrastRatio = (fg, bg) => {
            const lumFg = 0.2126 * toLuminance(fg.r) + 0.7152 * toLuminance(fg.g) + 0.0722 * toLuminance(fg.b);
            const lumBg = 0.2126 * toLuminance(bg.r) + 0.7152 * toLuminance(bg.g) + 0.0722 * toLuminance(bg.b);
            const lighter = Math.max(lumFg, lumBg);
            const darker = Math.min(lumFg, lumBg);
            return (lighter + 0.05) / (darker + 0.05);
        };
        const getOpaqueBackground = (el) => {
            let current = el;
            while (current) {
                const color = parseColor(window.getComputedStyle(current).backgroundColor || '');
                if (color && color.a > 0.98) return color;
                current = current.parentElement;
            }
            const bodyColor = parseColor(window.getComputedStyle(document.body).backgroundColor || '');
            return bodyColor && bodyColor.a > 0.98 ? bodyColor : { r: 255, g: 255, b: 255, a: 1 };
        };

        const contrastProblems = contentElements
            .filter((el) => isVisible(el))
            .flatMap((el) => {
                const text = norm(el.textContent);
                if (!text || text.length < 2 || el.children.length > 0) return [];
                if (el.classList.contains('material-icons') || el.closest('.material-icons')) return [];
                if (el.closest('.navbar') || el.closest('.wb-footer')) return [];
                const disabledAncestor = el.closest('button, [role="button"], input, select, textarea, .btn');
                if (disabledAncestor && isDisabled(disabledAncestor)) return [];
                const style = window.getComputedStyle(el);
                const color = parseColor(style.color || '');
                if (!color || color.a < 0.99) return [];
                if ((style.backgroundImage || 'none') !== 'none') return [];
                // Note: This skips semi-transparent backgrounds (known limitation)
                // Elements with stacked semi-transparent layers may produce false positives/negatives
                const bg = getOpaqueBackground(el);
                const ratio = contrastRatio(color, bg);
                const fontSize = Number.parseFloat(style.fontSize || '16');
                const fontWeight = Number.parseInt(style.fontWeight || '400', 10);
                const isLargeText = fontSize >= constants.WCAG_LARGE_TEXT_SIZE_PX ||
                    (fontSize >= constants.WCAG_LARGE_TEXT_SIZE_BOLD_PX && fontWeight >= constants.WCAG_BOLD_WEIGHT);
                const minimum = isLargeText ? constants.WCAG_LARGE_AA : constants.WCAG_NORMAL_AA;
                if (ratio >= minimum) return [];
                return [{
                    tag: el.tagName,
                    id: el.id || null,
                    text: text.slice(0, 80),
                    ratio: round(ratio),
                    minimum,
                }];
            })
            .sort((a, b) => a.ratio - b.ratio)
            .slice(0, 20);

        const layoutShift = window.__uiLintLayoutShift || { value: 0, count: 0 };

        const collectComponentRects = () => Array.from(contentRoot.querySelectorAll('.card, .leaflet-container, svg, canvas, table'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((el) => {
                const rect = el.getBoundingClientRect();
                return rect.width >= 32 && rect.height >= 32;
            })
            .map((el, index) => {
                const rect = el.getBoundingClientRect();
                return {
                    key: `${el.tagName}:${el.id || ''}:${typeof el.className === 'string' ? el.className : ''}:${index}`,
                    rect: {
                        width: rect.width,
                        height: rect.height,
                    },
                    element: el,
                };
            });

        const componentRectsBefore = collectComponentRects();
        await new Promise((resolve) => window.setTimeout(resolve, constants.COMPONENT_LAYOUT_SHIFT_SETTLE_MS));
        const componentRectsAfter = collectComponentRects();
        const componentRectsAfterMap = new Map(componentRectsAfter.map((entry) => [entry.key, entry]));
        const componentLayoutShift = componentRectsBefore
            .map((beforeEntry) => {
                const afterEntry = componentRectsAfterMap.get(beforeEntry.key);
                if (!afterEntry) return null;

                const deltaHeight = Math.abs(afterEntry.rect.height - beforeEntry.rect.height);
                const deltaWidth = Math.abs(afterEntry.rect.width - beforeEntry.rect.width);
                if (
                    deltaHeight <= constants.COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX &&
                    deltaWidth <= constants.COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX
                ) {
                    return null;
                }

                return {
                    before: {
                        width: round(beforeEntry.rect.width),
                        height: round(beforeEntry.rect.height),
                    },
                    after: {
                        width: round(afterEntry.rect.width),
                        height: round(afterEntry.rect.height),
                    },
                    deltaWidth: round(deltaWidth),
                    deltaHeight: round(deltaHeight),
                    component: rectInfo(afterEntry.element),
                };
            })
            .filter(Boolean)
            .slice(0, 20);

        const spacing = {};
        const cardContainment = {
            cardsPastFooter: [],
        };

        spacing.mobileRowCardStackGaps = [];
        if (window.matchMedia('(max-width: 991.98px)').matches) {
            spacing.mobileRowCardStackGaps = Array.from(contentRoot.querySelectorAll('.row'))
                .filter((row) => {
                    const classes = Array.from(row.classList);
                    return classes.some((c) => /^g[xy]?-[1-5]$/.test(c));
                })
                .map((row) => {
                    const rowLabel = row.id
                        || row.getAttribute('data-ui-lint')
                        || Array.from(row.classList).join(' ')
                        || 'row';
                    const cards = Array.from(row.children)
                        .filter((child) => hasBootstrapColClass(child) && isVisible(child))
                        .flatMap((col) => Array.from(col.children)
                            .filter((child) => child.classList?.contains('card') && isVisible(child))
                            .map((card) => ({
                                label: norm(card.querySelector('.card-header')?.textContent).slice(0, 80) || 'card',
                                rect: card.getBoundingClientRect(),
                            })))
                        .sort((a, b) => {
                            if (Math.abs(a.rect.top - b.rect.top) > 1) return a.rect.top - b.rect.top;
                            return a.rect.left - b.rect.left;
                        });

                    const gaps = [];
                    for (let index = 1; index < cards.length; index += 1) {
                        const prev = cards[index - 1];
                        const current = cards[index];
                        if (Math.abs(prev.rect.left - current.rect.left) >= 4) continue;
                        if (current.rect.top < prev.rect.bottom - 1) continue;
                        gaps.push({
                            from: prev.label,
                            to: current.label,
                            gap: round(current.rect.top - prev.rect.bottom),
                        });
                    }

                    const gapValues = gaps.map((entry) => entry.gap);
                    const gapVariance = gapValues.length > 1
                        ? round(Math.max(...gapValues) - Math.min(...gapValues))
                        : 0;

                    return {
                        row: rowLabel,
                        cardCount: cards.length,
                        gaps,
                        gapVariance,
                        gapsConsistent: gapVariance <= constants.STACK_GAP_VARIANCE_TOLERANCE_PX,
                    };
                })
                .filter((entry) => entry.cardCount >= 3 && entry.gaps.length >= 2)
                .slice(0, 20);
        }

        const footer = document.querySelector('.wb-footer');
        const pageHasVerticalOverflow = Math.max(
            contentRoot.scrollHeight,
            document.documentElement.scrollHeight,
            document.body.scrollHeight
        ) > Math.max(contentRoot.clientHeight, window.innerHeight) + 2;
        if (footer && !pageHasVerticalOverflow) {
            const footerRect = footer.getBoundingClientRect();
            cardContainment.cardsPastFooter = Array.from(contentRoot.querySelectorAll('.card'))
                .filter((card) => isVisible(card))
                .filter((card) => {
                    const rect = card.getBoundingClientRect();
                    return rect.top < footerRect.top && rect.bottom > footerRect.top + constants.FOOTER_OVERLAP_TOLERANCE_PX;
                })
                .slice(0, 20)
                .map(rectInfo);
        }

        const measureStandardMainGridGap = () => {
            const mainGridRow = document.querySelector('.wb-main-grid');
            const statsRow = mainGridRow?.previousElementSibling;
            if (!mainGridRow || !statsRow || !statsRow.classList.contains('row')) return;
            const statsRect = statsRow.getBoundingClientRect();
            const mainRect = mainGridRow.getBoundingClientRect();
            spacing.rowToRowGap = round(mainRect.top - statsRect.bottom);
            spacing.rowToRowGapInRange =
                spacing.rowToRowGap >= constants.VERTICAL_GAP_MIN &&
                spacing.rowToRowGap <= constants.VERTICAL_GAP_MAX;
        };

        if (scope === 'dashboard' || scope === 'dns') {
            measureStandardMainGridGap();
        }

        if (scope === 'dashboard') {
            const statCards = Array.from(document.querySelectorAll('.dashboard-stats-row > div .card')).slice(0, 4);
            spacing.statCardWidths = statCards.map((card) => round(card.getBoundingClientRect().width));

            const topRowColumns = Array.from(document.querySelectorAll('.row.g-3.mb-3 > .col-lg-6'))
                .filter((el) => isVisible(el))
                .slice(0, 2);
            if (topRowColumns.length === 2) {
                const heights = topRowColumns.map((col) => round(col.getBoundingClientRect().height));
                spacing.dashboardTopRowAlignment = {
                    heights,
                    variance: round(Math.abs(heights[0] - heights[1])),
                    aligned: Math.abs(heights[0] - heights[1]) <= 4,
                };
            }

            const mapCard = document.querySelector('.dashboard-map-col .card');
            const recentCard = document.querySelector('.dashboard-recent-peers-col .card');
            const speedCard = document.querySelector('.dashboard-speedtest-col .card');

            // Mobile stack order is intentional: Speedtest -> Peer Locations -> Recent Peer Activity.
            if (mapCard && recentCard && speedCard && window.matchMedia('(max-width: 767.98px)').matches) {
                const mapRect = mapCard.getBoundingClientRect();
                const recentRect = recentCard.getBoundingClientRect();
                const speedRect = speedCard.getBoundingClientRect();
                spacing.dashboardMobileStackOrder = {
                    speedtestAboveMap: speedRect.top <= mapRect.top + 2,
                    mapAboveRecent: mapRect.top <= recentRect.top + 2,
                    speedTop: round(speedRect.top),
                    mapTop: round(mapRect.top),
                    recentTop: round(recentRect.top),
                };
            }

            // Detect desktop-style layout using Bootstrap breakpoint
            if (mapCard && recentCard && speedCard && window.matchMedia('(min-width: 1200px)').matches) {
                const mapRect = mapCard.getBoundingClientRect();
                const recentRect = recentCard.getBoundingClientRect();
                const speedRect = speedCard.getBoundingClientRect();
                spacing.desktopColumnAlignment = {
                    mapBottom: round(mapRect.bottom),
                    recentBottom: round(recentRect.bottom),
                    bottomDelta: round(Math.abs(mapRect.bottom - recentRect.bottom)),
                    speedBottom: round(speedRect.bottom),
                    verticalGap: round(recentRect.top - speedRect.bottom),
                };
            }
        }

        if (scope === 'settings') {
            const activePane = document.querySelector('#settingsTabContent > .tab-pane.active');
            const cardRects = activePane
                ? Array.from(activePane.querySelectorAll('.card'))
                    .filter((card) => isVisible(card))
                    .map((card) => card.getBoundingClientRect())
                : [];
            const verticalGaps = [];
            for (let index = 1; index < cardRects.length; index += 1) {
                const prev = cardRects[index - 1];
                const current = cardRects[index];
                if (Math.abs(prev.left - current.left) < 4 && current.top >= prev.bottom) {
                    verticalGaps.push(round(current.top - prev.bottom));
                }
            }
            spacing.activePaneId = activePane?.id || null;
            spacing.verticalGaps = verticalGaps;
            spacing.outlierVerticalGaps = verticalGaps.filter((gap) => gap > constants.VERTICAL_GAP_MAX || gap < constants.VERTICAL_GAP_MIN);

            const settingsPrimaryColor = parseColor(
                getComputedStyle(document.documentElement).getPropertyValue('--bs-primary').trim()
                || getComputedStyle(document.documentElement).getPropertyValue('--wb-primary').trim()
                || ''
            );
            spacing.settingsTabColors = Array.from(document.querySelectorAll('#settingsTabs .nav-link.active'))
                .filter((el) => isVisible(el))
                .map((el) => {
                    const style = window.getComputedStyle(el);
                    const color = parseColor(style.color || '');
                    const delta = colorDistance(color, settingsPrimaryColor);
                    return {
                        id: el.id || null,
                        text: norm(el.textContent),
                        color: normalizeColor(style.color),
                        primaryColor: settingsPrimaryColor
                            ? `rgb(${settingsPrimaryColor.r},${settingsPrimaryColor.g},${settingsPrimaryColor.b})`
                            : null,
                        colorDelta: delta == null ? null : round(delta),
                    };
                });

            if (activePane?.id === 'logs-pane') {
                const logCards = Array.from(activePane.querySelectorAll('.card'))
                    .filter((card) => isVisible(card));
                const deleteBlocks = Array.from(activePane.querySelectorAll('.metrics-delete'))
                    .filter((el) => isVisible(el));
                const deleteInners = Array.from(activePane.querySelectorAll('.metrics-delete-inner'))
                    .filter((el) => isVisible(el));
                const deleteHairlines = Array.from(activePane.querySelectorAll('.metrics-delete hr'))
                    .filter((el) => isVisible(el));
                const hairlineTops = deleteHairlines.map((el) => round(el.getBoundingClientRect().top));
                const hairlineVariance = hairlineTops.length > 1
                    ? round(Math.max(...hairlineTops) - Math.min(...hairlineTops))
                    : 0;

                spacing.logsDeleteLayout = {
                    cardCount: logCards.length,
                    deleteBlockCount: deleteBlocks.length,
                    deleteInnerCount: deleteInners.length,
                    hairlineCount: deleteHairlines.length,
                    hairlineTops,
                    hairlineVariance,
                    hairlineAligned: hairlineVariance <= constants.LOGS_DELETE_HAIRLINE_TOLERANCE_PX,
                };

                const metricPaths = Array.from(activePane.querySelectorAll('.settings-storage-path'))
                    .filter((el) => isVisible(el))
                    .map((el) => {
                        const style = window.getComputedStyle(el);
                        const range = document.createRange();
                        range.selectNodeContents(el);
                        const lineRects = Array.from(range.getClientRects())
                            .filter((rect) => rect.width > 0 && rect.height > 0);
                        return {
                            id: el.id || null,
                            text: norm(el.textContent),
                            whiteSpace: style.whiteSpace,
                            textOverflow: style.textOverflow,
                            overflowX: style.overflowX,
                            wraps: style.whiteSpace === 'nowrap' ? false : lineRects.length > 1,
                        };
                    });

                spacing.logsPathLayout = metricPaths;
            }

            // Compact action rows inside settings cards should sit close to the
            // preceding content and must not introduce divider hairlines.
            spacing.compactCardActionRows = Array.from(
                activePane?.querySelectorAll('.card-body > .d-flex.justify-content-end.align-items-center') ?? []
            )
                .filter((el) => isVisible(el))
                .filter((el) => el.querySelector('.btn'))
                .map((el) => {
                    const style = window.getComputedStyle(el);
                    const buttons = Array.from(el.querySelectorAll('.btn'))
                        .filter((btn) => isVisible(btn));
                    const marginTop = Number.parseFloat(style.marginTop || '0');
                    const paddingTop = Number.parseFloat(style.paddingTop || '0');
                    const borderTopWidth = Number.parseFloat(style.borderTopWidth || '0');
                    const hasBorderTopClass = el.classList.contains('border-top');
                    const isCompactMargin = marginTop <= constants.COMPACT_CARD_ACTION_MARGIN_TOP_MAX_PX;
                    const isCompactPadding = paddingTop <= constants.COMPACT_CARD_ACTION_PADDING_TOP_MAX_PX;
                    const isBorderless = !hasBorderTopClass && borderTopWidth <= constants.COMPACT_CARD_ACTION_BORDER_TOP_MAX_PX;

                    return {
                        ...rectInfo(el),
                        classList: Array.from(el.classList),
                        buttonCount: buttons.length,
                        buttonIds: buttons.map((btn) => btn.id || null).filter(Boolean),
                        marginTop: round(marginTop),
                        paddingTop: round(paddingTop),
                        borderTopWidth: round(borderTopWidth),
                        hasBorderTopClass,
                        isCompactMargin,
                        isCompactPadding,
                        isBorderless,
                    };
                });

            // Retention slider tick alignment validation
            const sliderScales = Array.from(activePane?.querySelectorAll('.retention-scale') ?? [])
                .filter((el) => isVisible(el));
            spacing.sliderAlignment = sliderScales.map((scale) => {
                const slider = scale.querySelector('input[type="range"]');
                const tickContainer = scale.querySelector('.retention-ticks');
                const labelContainer = scale.querySelector('.retention-labels');
                if (!slider || !tickContainer) return null;

                const sliderRect = slider.getBoundingClientRect();
                const ticks = Array.from(tickContainer.querySelectorAll('.retention-tick'));
                const labels = labelContainer
                    ? Array.from(labelContainer.querySelectorAll('.retention-label'))
                    : [];

                const thumbSize = Number.parseFloat(
                    window.getComputedStyle(scale).getPropertyValue('--thumb-size') || '16'
                );
                const trackLeft = sliderRect.left + thumbSize / 2;
                const trackRight = sliderRect.right - thumbSize / 2;
                const trackWidth = trackRight - trackLeft;
                const max = Number(slider.max) || 1;

                const tickIssues = ticks.map((tick, idx) => {
                    const tickRect = tick.getBoundingClientRect();
                    const tickCenter = tickRect.left + tickRect.width / 2;
                    const iValue = Number(
                        window.getComputedStyle(tick).getPropertyValue('--i') || idx
                    );
                    const expectedCenter = trackLeft + (iValue / max) * trackWidth;
                    const delta = Math.abs(tickCenter - expectedCenter);
                    return delta > constants.SLIDER_TICK_ALIGNMENT_TOLERANCE_PX
                        ? { index: idx, delta: round(delta), expected: round(expectedCenter), actual: round(tickCenter) }
                        : null;
                }).filter(Boolean);

                const labelMetrics = labels.map((label, idx) => {
                    const style = window.getComputedStyle(label);
                    const labelRect = label.getBoundingClientRect();
                    const iValue = Number(
                        style.getPropertyValue('--i') || idx
                    );
                    const opacity = Number.parseFloat(style.opacity || '1');
                    const hidden = style.display === 'none'
                        || style.visibility === 'hidden'
                        || opacity <= constants.SLIDER_LABEL_HIDDEN_OPACITY_MAX
                        || labelRect.width === 0
                        || labelRect.height === 0;

                    let alignment = 'center';
                    let expected = trackLeft + (iValue / max) * trackWidth;
                    let actual = labelRect.left + labelRect.width / 2;

                    if (iValue <= 0) {
                        alignment = 'start';
                        expected = trackLeft;
                        actual = labelRect.left;
                    } else if (iValue >= max) {
                        alignment = 'end';
                        expected = trackRight;
                        actual = labelRect.right;
                    }

                    return {
                        index: idx,
                        hidden,
                        text: (label.textContent || '').replace(/\s+/g, ' ').trim(),
                        left: round(labelRect.left),
                        right: round(labelRect.right),
                        alignment,
                        expected: round(expected),
                        actual: round(actual),
                        delta: round(Math.abs(actual - expected)),
                    };
                });

                const labelIssues = labelMetrics
                    .filter((label) => !label.hidden && label.delta > constants.SLIDER_TICK_ALIGNMENT_TOLERANCE_PX)
                    .map((label) => ({
                        index: label.index,
                        delta: label.delta,
                        alignment: label.alignment,
                        expected: label.expected,
                        actual: label.actual,
                    }));

                const visibleLabels = labelMetrics.filter((label) => !label.hidden);
                const labelOverlap = [];
                for (let index = 1; index < visibleLabels.length; index += 1) {
                    const prev = visibleLabels[index - 1];
                    const current = visibleLabels[index];
                    const gap = current.left - prev.right;
                    if (gap < constants.SLIDER_VISIBLE_LABEL_GAP_MIN_PX) {
                        labelOverlap.push({
                            leftIndex: prev.index,
                            rightIndex: current.index,
                            gap: round(gap),
                            leftText: prev.text,
                            rightText: current.text,
                        });
                    }
                }

                const sliderId = slider.id || null;
                const tickCount = ticks.length;
                const expectedTickCount = max + 1;
                const usesIndexVar = ticks.every((t) => t.style.getPropertyValue('--i') !== '');

                return {
                    sliderId,
                    tickCount,
                    expectedTickCount,
                    tickCountMatch: tickCount === expectedTickCount,
                    usesIndexVar,
                    visibleLabelCount: visibleLabels.length,
                    hiddenLabelCount: labelMetrics.length - visibleLabels.length,
                    tickMisaligned: tickIssues,
                    labelMisaligned: labelIssues,
                    labelOverlap,
                };
            }).filter(Boolean);
        }

        if (scope === 'users') {
            const actionButtons = Array.from(contentRoot.querySelectorAll(
                '.btn-edit-user, .btn-otp-settings, .btn-passkey-settings, .btn-delete-user, .btn-delete-passkey'
            ))
                .filter((el) => isVisible(el) && isInContentRoot(el))
                .map((el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    const icon = el.querySelector('.material-icons');
                    const iconStyle = icon ? window.getComputedStyle(icon) : null;
                    return {
                        ...rectInfo(el),
                        width: round(rect.width),
                        height: round(rect.height),
                        borderRadius: round(parseFloat(style.borderTopLeftRadius || '0')),
                        display: style.display,
                        alignItems: style.alignItems,
                        justifyContent: style.justifyContent,
                        hasUsersActionClass: el.classList.contains('users-action-btn'),
                        iconHasMdClass: Boolean(icon?.classList.contains('icon-md')),
                        iconPointerEvents: iconStyle?.pointerEvents || null,
                    };
                });

            const referenceButton = actionButtons[0] || null;
            spacing.usersActionButtons = {
                count: actionButtons.length,
                missingClassCount: actionButtons.filter((button) => !button.hasUsersActionClass).length,
                missingIconMdCount: actionButtons.filter((button) => !button.iconHasMdClass).length,
                undersizedCount: actionButtons.filter(
                    (button) => button.width < constants.CLICK_TARGET_MIN_SIZE_PX || button.height < constants.CLICK_TARGET_MIN_SIZE_PX
                ).length,
                alignmentMismatchCount: actionButtons.filter(
                    (button) => button.display !== 'inline-flex' || button.alignItems !== 'center' || button.justifyContent !== 'center'
                ).length,
                iconPointerMismatchCount: actionButtons.filter((button) => button.iconPointerEvents !== 'none').length,
                sizeMismatchCount: referenceButton
                    ? actionButtons.filter(
                        (button) => Math.abs(button.width - referenceButton.width) > 2 || Math.abs(button.height - referenceButton.height) > 2
                    ).length
                    : 0,
                borderRadiusMismatchCount: referenceButton
                    ? actionButtons.filter((button) => Math.abs(button.borderRadius - referenceButton.borderRadius) > 1).length
                    : 0,
                sample: actionButtons.slice(0, 10),
            };
        }

        // Peers page: Modal form validation (required field markers)
        if (scope === 'peers') {
            const addPeerModal = document.getElementById('addPeerModal');
            const editPeerModal = document.getElementById('editPeerModal');

            const validatePeerModal = (modal, modalName) => {
                if (!modal) return { found: false, modalName };

                const nameInput = modal.querySelector('#peer-name') || modal.querySelector('#edit-peer-name');
                const nameLabel = nameInput ? modal.querySelector(`label[for="${nameInput.id}"]`) : null;

                const hasRequiredAttr = nameInput?.hasAttribute('required') ?? false;
                const hasMaxLength = nameInput?.hasAttribute('maxlength') ?? false;
                const maxLengthValue = nameInput?.getAttribute('maxlength') ?? null;

                // Check for required field visual marker (red asterisk)
                const hasRequiredMarker = nameLabel
                    ? Boolean(nameLabel.querySelector('span.text-danger'))
                    : false;

                return {
                    found: true,
                    modalName,
                    nameInputId: nameInput?.id ?? null,
                    hasRequiredAttr,
                    hasMaxLength,
                    maxLengthValue,
                    hasRequiredMarker,
                    valid: hasRequiredAttr && hasRequiredMarker,
                };
            };

            spacing.peersModalValidation = {
                addPeerModal: validatePeerModal(addPeerModal, 'addPeerModal'),
                editPeerModal: validatePeerModal(editPeerModal, 'editPeerModal'),
            };

            // Desktop layout: Status cell must NOT use display:flex (breaks table-cell vertical alignment)
            // Also check Status badges don't overlap Action buttons horizontally
            if (window.innerWidth >= 768) {
                const peerRows = Array.from(document.querySelectorAll('#peers-table tr[data-peer-id]'));
                spacing.peersDesktopStatusCell = peerRows.slice(0, 5).map((row) => {
                    const statusCell = row.querySelector('td[data-label="Status"]');
                    const actionsCell = row.querySelector('td.peer-actions-cell');
                    const display = statusCell ? window.getComputedStyle(statusCell).display : null;
                    const statusRect = statusCell ? statusCell.getBoundingClientRect() : null;
                    const actionsRect = actionsCell ? actionsCell.getBoundingClientRect() : null;
                    const overlapsActions = (statusRect && actionsRect)
                        ? statusRect.right > actionsRect.left + 2
                        : false;
                    return {
                        peerId: row.dataset.peerId,
                        statusDisplay: display,
                        isTableCell: display === 'table-cell',
                        overlapsActions,
                        statusRight: statusRect ? Math.round(statusRect.right) : null,
                        actionsLeft: actionsRect ? Math.round(actionsRect.left) : null,
                    };
                });
            }

            // Mobile layout: badge visibility, last-seen merged into badge, client-ip placement
            if (window.innerWidth < 768) {
                const peerRows = Array.from(document.querySelectorAll('#peers-table tr[data-peer-id]'));
                spacing.peersMobileLayout = peerRows.slice(0, 10).map((row) => {
                    const peerId = row.dataset.peerId;
                    const statusCell = row.querySelector('td[data-label="Status"]');
                    const connectionBadge = statusCell?.querySelector('.peer-connection-badge-mobile');
                    const enabledBadge = statusCell?.querySelector('.peer-enabled-badge');
                    const lastSeenCell = row.querySelector('.peer-last-seen');
                    const clientIpCell = row.querySelector('.peer-client-ip');
                    const vpnCell = row.querySelector('td[data-label="VPN Address"]');
                    const nameCell = row.querySelector('td[data-label="Name"]');

                    const connVisible = connectionBadge ? window.getComputedStyle(connectionBadge).display !== 'none' : false;
                    const enabledVisible = enabledBadge ? window.getComputedStyle(enabledBadge).display !== 'none' : false;
                    const lastSeenHidden = lastSeenCell ? window.getComputedStyle(lastSeenCell).display === 'none' : true;
                    const badgeTimeSpan = connectionBadge?.querySelector('.peer-badge-time');
                    const badgeTimeVisible = badgeTimeSpan ? window.getComputedStyle(badgeTimeSpan).display !== 'none' : false;

                    // Check status badges are right-aligned at the same vertical level as name
                    const nameRect = nameCell ? nameCell.getBoundingClientRect() : null;
                    const statusRect = statusCell ? statusCell.getBoundingClientRect() : null;
                    const statusAlignedWithName = (nameRect && statusRect)
                        ? Math.abs(nameRect.top - statusRect.top) < 8
                        : false;

                    // Check client-ip is below VPN address (stacked layout)
                    const vpnRect = vpnCell ? vpnCell.getBoundingClientRect() : null;
                    const clientIpRect = clientIpCell ? clientIpCell.getBoundingClientRect() : null;
                    const clientIpStyle = clientIpCell ? window.getComputedStyle(clientIpCell) : null;
                    const clientIpVisible = clientIpStyle ? clientIpStyle.display !== 'none' : false;
                    const clientIpBelowVpn = (vpnRect && clientIpRect && clientIpVisible)
                        ? clientIpRect.top >= vpnRect.bottom - 4
                        : true; // pass if client-ip is hidden (empty)

                    return {
                        peerId,
                        connectionBadgeVisible: connVisible,
                        enabledBadgeVisible: enabledVisible,
                        lastSeenCellHidden: lastSeenHidden,
                        badgeTimeVisible,
                        statusAlignedWithName,
                        clientIpBelowVpn,
                    };
                });
            }
        }

        if (scope === 'about') {
            const changelogCard = document.querySelector('.about-changelog-col .card');
            const changelogBody = document.querySelector('.about-changelog-col .card-body');
            const depsCard = document.querySelector('.about-deps-col .card');
            const aboutDetailsCard = Array.from(document.querySelectorAll('.about-top-row .card'))
                .find((card) => norm(card.querySelector('.card-header')?.textContent).includes('Application Details'));
            const aboutDetailsRows = aboutDetailsCard
                ? Array.from(aboutDetailsCard.querySelectorAll('tbody tr'))
                    .map((row) => norm(row.querySelector('td:first-child')?.textContent))
                    .filter(Boolean)
                : [];
            const missingDetailsRows = constants.ABOUT_APPLICATION_DETAILS_REQUIRED_ROWS
                .filter((label) => !aboutDetailsRows.includes(label));
            const forbiddenDetailsRows = aboutDetailsRows
                .filter((label) => constants.ABOUT_APPLICATION_DETAILS_FORBIDDEN_ROWS.includes(label));
            const aboutReferenceValue = document.querySelector('.about-reference-value');
            const aboutReferenceStyle = aboutReferenceValue ? window.getComputedStyle(aboutReferenceValue) : null;
            const aboutReferenceMetrics = aboutReferenceStyle ? {
                color: normalizeColor(aboutReferenceStyle.color),
                fontSize: Number.parseFloat(aboutReferenceStyle.fontSize || '0'),
                backgroundColor: normalizeColor(aboutReferenceStyle.backgroundColor),
            } : null;
            const updateLabelRows = Array.from(document.querySelectorAll('#update-check-result tbody tr'))
                .map((row) => {
                    const labelCell = row.querySelector('td:first-child');
                    const labelText = norm(labelCell?.textContent);
                    const labelStrong = labelCell?.querySelector('strong');
                    return {
                        label: labelText,
                        hasStrong: Boolean(labelStrong && norm(labelStrong.textContent) === labelText),
                    };
                })
                .filter((row) => row.label);
            const missingBoldUpdateLabels = constants.ABOUT_UPDATE_TABLE_LABELS
                .filter((label) => updateLabelRows.some((row) => row.label === label && !row.hasStrong));
            const updateValueStyleMismatches = aboutReferenceMetrics
                ? Array.from(document.querySelectorAll('.about-update-value'))
                    .filter((el) => isVisible(el))
                    .map((el) => {
                        const style = window.getComputedStyle(el);
                        const color = normalizeColor(style.color);
                        const fontSize = Number.parseFloat(style.fontSize || '0');
                        const backgroundColor = normalizeColor(style.backgroundColor);
                        const reasons = [];

                        if (color !== aboutReferenceMetrics.color) {
                            reasons.push('color');
                        }
                        if (Math.abs(fontSize - aboutReferenceMetrics.fontSize) > 0.5) {
                            reasons.push('fontSize');
                        }
                        if (backgroundColor !== aboutReferenceMetrics.backgroundColor) {
                            reasons.push('backgroundColor');
                        }

                        if (!reasons.length) return null;

                        return {
                            text: norm(el.textContent).slice(0, 60),
                            id: el.id || null,
                            reasons,
                            color,
                            fontSize: round(fontSize),
                            backgroundColor,
                            reference: {
                                color: aboutReferenceMetrics.color,
                                fontSize: round(aboutReferenceMetrics.fontSize),
                                backgroundColor: aboutReferenceMetrics.backgroundColor,
                            },
                        };
                    })
                    .filter(Boolean)
                : [];

            // About page card layout validation (reference layout pattern)
            // Validates that cards in the same row have consistent heights (flexbox equal-height pattern)
            const desktopTopRowLayoutActive = window.matchMedia('(min-width: 992px)').matches;
            const topRowCards = Array.from(document.querySelectorAll('.about-top-row .card'))
                .filter((el) => isVisible(el));
            const topRowPrimaryCards = Array.from(document.querySelectorAll('.about-top-row > [class*="col-"] > .card:first-child'))
                .filter((el) => isVisible(el));
            const topRowPrimaryHeights = topRowPrimaryCards.map((card) => round(card.getBoundingClientRect().height));
            const topRowPrimaryMaxHeight = Math.max(...topRowPrimaryHeights);
            const topRowPrimaryMinHeight = Math.min(...topRowPrimaryHeights);
            const topRowHeightVariance = topRowPrimaryHeights.length > 1
                ? topRowPrimaryMaxHeight - topRowPrimaryMinHeight
                : 0;
            const topRowHeightsMatch = !desktopTopRowLayoutActive
                || topRowHeightVariance <= constants.ABOUT_TOP_ROW_HEIGHT_TOLERANCE_PX;
            const topRowFillerCards = Array.from(document.querySelectorAll('.about-top-row > [class*="col-"] > .about-doc-card'))
                .filter((el) => isVisible(el))
                .map((card) => {
                    const style = window.getComputedStyle(card);
                    return {
                        label: norm(card.textContent).slice(0, 80),
                        height: round(card.getBoundingClientRect().height),
                        flexGrow: Number.parseFloat(style.flexGrow || '0'),
                    };
                });
            // Filler cards should have flexGrow >= 1 to fill remaining space in their column
            const fillerCardsFillSpace = !desktopTopRowLayoutActive || !topRowFillerCards.length
                ? true
                : topRowFillerCards.every((card) => card.flexGrow >= 1);
            const mobileTopRowCards = topRowCards
                .map((card) => ({
                    label: norm(card.querySelector('.card-header')?.textContent).slice(0, 80),
                    rect: card.getBoundingClientRect(),
                }))
                .sort((a, b) => {
                    if (Math.abs(a.rect.top - b.rect.top) > 1) return a.rect.top - b.rect.top;
                    return a.rect.left - b.rect.left;
                });
            const mobileTopRowStackGaps = [];
            if (window.matchMedia('(max-width: 991.98px)').matches) {
                for (let index = 1; index < mobileTopRowCards.length; index += 1) {
                    const prev = mobileTopRowCards[index - 1];
                    const current = mobileTopRowCards[index];
                    if (Math.abs(prev.rect.left - current.rect.left) >= 4) continue;
                    if (current.rect.top < prev.rect.bottom - 1) continue;
                    mobileTopRowStackGaps.push({
                        from: prev.label,
                        to: current.label,
                        gap: round(current.rect.top - prev.rect.bottom),
                    });
                }
            }
            const mobileTopRowGapValues = mobileTopRowStackGaps.map((entry) => entry.gap);
            const mobileTopRowGapVariance = mobileTopRowGapValues.length > 1
                ? round(Math.max(...mobileTopRowGapValues) - Math.min(...mobileTopRowGapValues))
                : 0;
            const mobileTopRowGapsConsistent = mobileTopRowGapVariance <= constants.ABOUT_MOBILE_STACK_GAP_VARIANCE_TOLERANCE_PX;

            spacing.about = {
                changelogCardBottom: changelogCard ? round(changelogCard.getBoundingClientRect().bottom) : null,
                changelogBodyScrollHeight: changelogBody?.scrollHeight ?? null,
                changelogBodyClientHeight: changelogBody?.clientHeight ?? null,
                depsCardBottom: depsCard ? round(depsCard.getBoundingClientRect().bottom) : null,
                footerTop: footer ? round(footer.getBoundingClientRect().top) : null,
                detailsRows: aboutDetailsRows,
                missingDetailsRows,
                forbiddenDetailsRows,
                missingBoldUpdateLabels,
                updateValueStyleMismatches,
                // Reference layout metrics (About page is the reference for card grid layouts)
                topRowLayout: {
                    active: desktopTopRowLayoutActive,
                    cardCount: topRowCards.length,
                    primaryCardCount: topRowPrimaryCards.length,
                    heights: topRowPrimaryHeights,
                    heightsMatch: topRowHeightsMatch,
                    variance: topRowHeightVariance,
                    fillerCardCount: topRowFillerCards.length,
                    fillerCards: topRowFillerCards,
                    fillerCardsFillSpace,
                    pattern: 'equal-height-columns-with-filler-card',
                },
                mobileTopRowStack: {
                    active: window.matchMedia('(max-width: 991.98px)').matches,
                    gaps: mobileTopRowStackGaps,
                    gapVariance: mobileTopRowGapVariance,
                    gapsConsistent: mobileTopRowGapsConsistent,
                },
            };
        }

        // =============================================================================
        // Nodes page: Table responsiveness validation
        // =============================================================================
        // Desktop (>= 768px): Standard table layout with all columns visible
        // Mobile (< 768px): CSS Grid card layout with:
        //   - name/status in top row, fqdn spanning full width, meta line, actions
        //   - thead hidden, Port/Version/Peers/LastSeen columns hidden
        //   - .node-mobile-meta visible with version + port + peers + last seen
        if (scope === 'nodes') {
            const nodesTable = document.querySelector('.nodes-table');
            const isMobile = window.innerWidth < 768;

            // Mobile layout: grid card layout validation
            if (isMobile && nodesTable) {
                const nodeRows = Array.from(nodesTable.querySelectorAll('tbody tr[id^="node-row-"]'));
                spacing.nodesMobileLayout = nodeRows.slice(0, 10).map((row) => {
                    const nameCell = row.querySelector('td[data-label="Name"]');
                    const statusCell = row.querySelector('td[data-label="Status"]');
                    const fqdnCell = row.querySelector('td[data-label="FQDN"]');
                    const portCell = row.querySelector('td[data-label="Port"]');
                    const versionCell = row.querySelector('td[data-label="Version"]');
                    const peersCell = row.querySelector('td[data-label="Peers"]');
                    const lastSeenCell = row.querySelector('td[data-label="Last Seen"]');
                    const mobileMeta = row.querySelector('.node-mobile-meta');
                    const actionsCell = row.querySelector('td[data-label="Actions"]');

                    const thead = nodesTable.querySelector('thead');
                    const theadHidden = thead ? window.getComputedStyle(thead).display === 'none' : true;

                    const portHidden = portCell ? window.getComputedStyle(portCell).display === 'none' : true;
                    const versionHidden = versionCell ? window.getComputedStyle(versionCell).display === 'none' : true;
                    const peersHidden = peersCell ? window.getComputedStyle(peersCell).display === 'none' : true;
                    const lastSeenHidden = lastSeenCell ? window.getComputedStyle(lastSeenCell).display === 'none' : true;
                    const mobileMetaVisible = mobileMeta ? window.getComputedStyle(mobileMeta).display !== 'none' : false;

                    // Verify grid layout is applied
                    const rowDisplay = window.getComputedStyle(row).display;
                    const isGridLayout = rowDisplay === 'grid';

                    // Check name and status are on the same row (aligned vertically)
                    const nameRect = nameCell ? nameCell.getBoundingClientRect() : null;
                    const statusRect = statusCell ? statusCell.getBoundingClientRect() : null;
                    const statusAlignedWithName = (nameRect && statusRect)
                        ? Math.abs(nameRect.top - statusRect.top) < 8
                        : false;

                    // Check fqdn spans full width below name
                    const fqdnRect = fqdnCell ? fqdnCell.getBoundingClientRect() : null;
                    const fqdnBelowName = (nameRect && fqdnRect)
                        ? fqdnRect.top >= nameRect.bottom - 4
                        : false;

                    // Check actions cell has border-top separator
                    const actionsStyle = actionsCell ? window.getComputedStyle(actionsCell) : null;
                    const actionsBorderTop = actionsStyle
                        ? Number.parseFloat(actionsStyle.borderTopWidth || '0') > 0
                        : false;

                    return {
                        nodeId: row.id,
                        theadHidden,
                        isGridLayout,
                        portHidden,
                        versionHidden,
                        peersHidden,
                        lastSeenHidden,
                        mobileMetaVisible,
                        statusAlignedWithName,
                        fqdnBelowName,
                        actionsBorderTop,
                    };
                });
            }

            // Desktop layout: verify table structure
            if (!isMobile && nodesTable) {
                const nodeRows = Array.from(nodesTable.querySelectorAll('tbody tr[id^="node-row-"]'));
                const responsiveWrap = nodesTable.closest('.table-responsive');
                spacing.nodesDesktopTableWrapper = responsiveWrap ? {
                    hasHorizontalScroll: responsiveWrap.scrollWidth > responsiveWrap.clientWidth + 2,
                    scrollWidth: Math.round(responsiveWrap.scrollWidth),
                    clientWidth: Math.round(responsiveWrap.clientWidth),
                    overflowX: window.getComputedStyle(responsiveWrap).overflowX,
                    wrapper: rectInfo(responsiveWrap),
                } : null;
                spacing.nodesDesktopLayout = nodeRows.slice(0, 5).map((row) => {
                    const statusCell = row.querySelector('td[data-label="Status"]');
                    const actionsCell = row.querySelector('td[data-label="Actions"]');
                    const statusRect = statusCell ? statusCell.getBoundingClientRect() : null;
                    const actionsRect = actionsCell ? actionsCell.getBoundingClientRect() : null;
                    const overlapsActions = (statusRect && actionsRect)
                        ? statusRect.right > actionsRect.left + 2
                        : false;
                    return {
                        nodeId: row.id,
                        overlapsActions,
                        statusRight: statusRect ? Math.round(statusRect.right) : null,
                        actionsLeft: actionsRect ? Math.round(actionsRect.left) : null,
                    };
                });
            }
        }

        // Status page: Network flow diagram validation
        if (scope === 'status') {
            const flowWrapper = document.querySelector('[data-ui-lint="status-flow"]') || document.querySelector('.flow-wrapper');
            const flowNodes = Array.from((flowWrapper || document).querySelectorAll('.flow-node'))
                .filter((el) => isVisible(el));
            const flowConnectors = Array.from((flowWrapper || document).querySelectorAll('.flow-connector'))
                .filter((el) => isVisible(el));
            const flowWrapperRect = flowWrapper ? flowWrapper.getBoundingClientRect() : null;
            // Use Bootstrap breakpoint detection instead of raw width
            const desktopLayout = window.matchMedia('(min-width: 992px)').matches;
            const compactMobileLayout = window.matchMedia('(max-width: 575.98px)').matches;

            const flowNodeMetrics = flowNodes.map((node) => {
                const icon = node.querySelector('.material-icons.flow-icon');
                const label = node.querySelector('.flow-label');
                const meta = node.querySelector('.flow-meta');
                const style = window.getComputedStyle(node);
                const iconStyle = icon ? window.getComputedStyle(icon) : null;
                const labelStyle = label ? window.getComputedStyle(label) : null;
                const metaStyle = meta ? window.getComputedStyle(meta) : null;
                const rect = node.getBoundingClientRect();
                const nodeKey = node.getAttribute('data-flow-node') || null;
                const iconName = norm(icon?.textContent);
                const labelText = label ? norm(label.textContent) : null;

                return {
                    key: nodeKey,
                    width: round(rect.width),
                    height: round(rect.height),
                    left: round(rect.left),
                    right: round(rect.right),
                    top: round(rect.top),
                    bottom: round(rect.bottom),
                    borderWidth: Number.parseFloat(style.borderTopWidth || '0'),
                    borderRadius: Number.parseFloat(style.borderTopLeftRadius || '0'),
                    padding: Number.parseFloat(style.padding || '0'),
                    iconFontSize: Number.parseFloat(iconStyle?.fontSize || '0'),
                    labelFontSize: Number.parseFloat(labelStyle?.fontSize || '0'),
                    metaFontSize: Number.parseFloat(metaStyle?.fontSize || '0'),
                    hasActiveClass: node.classList.contains('flow-node-active'),
                    hasInactiveClass: node.classList.contains('flow-node-inactive'),
                    hasIcon: Boolean(icon),
                    hasLabel: Boolean(label),
                    hasMeta: Boolean(meta),
                    iconName,
                    labelText,
                    metaText: meta ? norm(meta.textContent) : null,
                };
            });

            const flowConnectorMetrics = flowConnectors.map((connector) => {
                const line = connector.querySelector('.flow-line');
                const lineStyle = line ? window.getComputedStyle(line) : null;
                const rect = connector.getBoundingClientRect();
                const lineRect = line ? line.getBoundingClientRect() : null;
                const connectorKey = connector.getAttribute('data-flow-connector') || line?.getAttribute('data-flow-line') || null;

                return {
                    key: connectorKey,
                    width: round(rect.width),
                    height: round(rect.height),
                    left: round(rect.left),
                    right: round(rect.right),
                    top: round(rect.top),
                    bottom: round(rect.bottom),
                    hasLine: Boolean(line),
                    lineHeight: lineRect ? round(lineRect.height) : (lineStyle ? Number.parseFloat(lineStyle.height || '0') : null),
                    lineWidth: lineRect ? round(lineRect.width) : (lineStyle ? Number.parseFloat(lineStyle.width || '0') : null),
                    hasAnimation: lineStyle ? lineStyle.animationName !== 'none' : false,
                    hasInactiveClass: line ? line.classList.contains('flow-line-inactive') : false,
                };
            });

            const flowHeightVariance = flowNodeMetrics.length > 1
                ? Math.max(...flowNodeMetrics.map(n => n.height)) - Math.min(...flowNodeMetrics.map(n => n.height))
                : 0;
            const flowWidthVariance = flowNodeMetrics.length > 1
                ? Math.max(...flowNodeMetrics.map((node) => node.width)) - Math.min(...flowNodeMetrics.map((node) => node.width))
                : 0;
            const flowPopulatedMetaCount = flowNodeMetrics.filter((node) => node.metaText).length;
            const orderedNodeKeys = flowNodeMetrics.map((node) => node.key);
            const orderedConnectorKeys = flowConnectorMetrics.map((connector) => connector.key);
            const expectedNodeKeys = constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => node.key);
            const expectedConnectorKeys = constants.STATUS_FLOW_CONNECTOR_EXPECTATIONS;
            const expectedNodeLabels = new Map(constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => [node.key, node.label]));
            const expectedNodeIcons = new Map(constants.STATUS_FLOW_NODE_EXPECTATIONS.map((node) => [node.key, node.icon]));
            const expectedHeightVarianceMax = flowPopulatedMetaCount > 0 && flowPopulatedMetaCount < flowNodeMetrics.length ? 24 : 5;
            const labelMismatches = flowNodeMetrics
                .filter((node) => node.key && expectedNodeLabels.has(node.key))
                .filter((node) => node.labelText !== expectedNodeLabels.get(node.key))
                .map((node) => ({ key: node.key, labelText: node.labelText, expected: expectedNodeLabels.get(node.key) }));
            const iconMismatches = flowNodeMetrics
                .filter((node) => node.key && expectedNodeIcons.has(node.key))
                .filter((node) => node.iconName !== expectedNodeIcons.get(node.key))
                .map((node) => ({ key: node.key, iconName: node.iconName, expected: expectedNodeIcons.get(node.key) }));
            const nodeStateConflicts = flowNodeMetrics
                .filter((node) => node.hasActiveClass === node.hasInactiveClass)
                .map((node) => ({ key: node.key, active: node.hasActiveClass, inactive: node.hasInactiveClass }));
            const nodeContentStateMismatches = flowNodeMetrics
                .filter((node) => {
                    const hasContent = Boolean(node.metaText);
                    return hasContent ? !node.hasActiveClass || node.hasInactiveClass : !node.hasInactiveClass || node.hasActiveClass;
                })
                .map((node) => ({
                    key: node.key,
                    metaText: node.metaText,
                    active: node.hasActiveClass,
                    inactive: node.hasInactiveClass,
                }));
            const expectedOrientation = desktopLayout ? 'horizontal' : 'vertical';
            const orientationIssues = [];

            if (flowNodeMetrics.length === expectedNodeKeys.length) {
                for (let index = 1; index < flowNodeMetrics.length; index += 1) {
                    const previous = flowNodeMetrics[index - 1];
                    const current = flowNodeMetrics[index];
                    if (desktopLayout) {
                        if (current.left <= previous.left || Math.abs(current.top - previous.top) > 8) {
                            orientationIssues.push({ index, expectedOrientation, previous, current });
                        }
                    } else if (current.top <= previous.top || Math.abs(current.left - previous.left) > 8) {
                        orientationIssues.push({ index, expectedOrientation, previous, current });
                    }
                }
            }

            const connectorOrientationIssues = flowConnectorMetrics.filter((connector) => {
                if (desktopLayout) {
                    return !((connector.lineWidth || 0) > (connector.lineHeight || 0));
                }
                return !((connector.lineHeight || 0) > (connector.lineWidth || 0));
            }).map((connector) => ({
                key: connector.key,
                width: connector.width,
                height: connector.height,
                lineWidth: connector.lineWidth,
                lineHeight: connector.lineHeight,
                expectedOrientation,
            }));
            const compactMobileIssues = compactMobileLayout
                ? {
                    nodes: flowNodeMetrics.filter((node) =>
                        node.padding > 11
                        || node.borderRadius > 11
                        || node.iconFontSize > 19.5
                        || node.labelFontSize > 12.5
                        || (node.metaText && node.metaFontSize > 11.8)
                    ),
                    connectors: flowConnectorMetrics.filter((connector) =>
                        connector.height > 18
                        || (connector.lineWidth || 0) > 2.5
                    ),
                }
                : { nodes: [], connectors: [] };

            spacing.statusFlow = {
                hasWrapper: Boolean(flowWrapper),
                wrapperWidth: flowWrapperRect ? round(flowWrapperRect.width) : null,
                wrapperHeight: flowWrapperRect ? round(flowWrapperRect.height) : null,
                expectedOrientation,
                nodeCount: flowNodes.length,
                connectorCount: flowConnectors.length,
                expectedNodeCount: 3, // Client, WireGuard, Internet
                expectedConnectorCount: 2,
                nodeCountMatch: flowNodes.length === 3,
                connectorCountMatch: flowConnectors.length === 2,
                nodeOrderMatches: orderedNodeKeys.join('|') === expectedNodeKeys.join('|'),
                connectorOrderMatches: orderedConnectorKeys.join('|') === expectedConnectorKeys.join('|'),
                nodes: flowNodeMetrics,
                connectors: flowConnectorMetrics,
                heightVariance: round(flowHeightVariance),
                widthVariance: round(flowWidthVariance),
                populatedMetaCount: flowPopulatedMetaCount,
                expectedHeightVarianceMax,
                allNodesHaveStructure: flowNodeMetrics.every(n => n.hasIcon && n.hasLabel && n.hasMeta),
                labelMismatches,
                iconMismatches,
                nodeStateConflicts,
                nodeContentStateMismatches,
                orientationIssues,
                connectorOrientationIssues,
                compactMobileLayout,
                compactMobileIssues,
            };

            const statusDetailCards = Array.from(document.querySelectorAll('.card'))
                .map((card) => {
                    const title = card.querySelector('.h6, h3');
                    const titleText = title ? norm(title.textContent) : null;
                    if (!titleText || !constants.STATUS_DETAIL_CARD_TITLES.includes(titleText)) {
                        return null;
                    }

                    const value = card.querySelector('.font-monospace');
                    const valueText = norm(value?.textContent);

                    return {
                        title: titleText,
                        hasValue: Boolean(value && valueText),
                        valueText,
                    };
                })
                .filter(Boolean);
            const emptyStatusDetailCards = statusDetailCards.filter((card) => !card.hasValue);

            // Status page: Status check cards monospace validation
            // "Last Speedtest" uses inline <span class="font-monospace"> children,
            // while DNS checks use font-monospace on the <p> itself.
            const statusCheckTitles = ['DNS Resolution', 'Last Speedtest', 'DNS Leak Indicator', 'Outbound IP Probe'];
            const statusCheckCards = Array.from(document.querySelectorAll('.card'))
                .filter((card) => {
                    const title = card.querySelector('.h6, h3');
                    return title && statusCheckTitles.includes(norm(title.textContent));
                })
                .map((card) => {
                    const title = card.querySelector('.h6, h3');
                    const detail = card.querySelector('p.small');
                    const titleText = title ? norm(title.textContent) : null;
                    const hasMonoOnP = detail ? detail.classList.contains('font-monospace') : false;
                    const hasMonoSpans = detail ? detail.querySelectorAll('span.font-monospace').length > 0 : false;
                    const hasMonospace = hasMonoOnP || hasMonoSpans;
                    const detailText = detail ? norm(detail.textContent).slice(0, 100) : null;

                    return {
                        title: titleText,
                        hasDetail: Boolean(detail),
                        hasMonospace,
                        detailText,
                        isMissing: Boolean(detail && !hasMonospace),
                    };
                });

            const statusCheckMonospaceMissing = statusCheckCards.filter((card) => card.isMissing);

            spacing.statusCheckMonospace = {
                cards: statusCheckCards,
                missing: statusCheckMonospaceMissing,
                allCorrect: statusCheckMonospaceMissing.length === 0,
            };
            spacing.statusDetailCards = {
                cards: statusDetailCards,
                empty: emptyStatusDetailCards,
                allPopulated: emptyStatusDetailCards.length === 0,
            };
        }

        let loginFailure = null;
        if (scope === 'login') {
            const errorAlert = document.getElementById('error-alert');
            const passwordInput = document.getElementById('password');
            const loginCard = document.querySelector('.login-card');
            const passwordStyle = passwordInput ? window.getComputedStyle(passwordInput) : null;
            const cardStyle = loginCard ? window.getComputedStyle(loginCard) : null;
            const borderColor = parseColor(passwordStyle?.borderTopColor || '');
            // Danger-like border heuristic updated for #ff6384 (rgb(255, 99, 132))
            const dangerLikeBorder = Boolean(
                borderColor
                && borderColor.r >= 180
                && borderColor.g <= 100
                && borderColor.b <= 140
            );

            loginFailure = {
                alertVisible: Boolean(errorAlert && isVisible(errorAlert)),
                errorText: norm(errorAlert?.textContent),
                passwordInvalidClass: Boolean(passwordInput?.classList.contains('is-invalid')),
                passwordAriaInvalid: passwordInput?.getAttribute('aria-invalid') === 'true',
                passwordBorderColor: passwordStyle?.borderTopColor || null,
                passwordBorderIsDangerLike: dangerLikeBorder,
                passwordBoxShadow: passwordStyle?.boxShadow || null,
                cardShakeClass: Boolean(loginCard?.classList.contains('login-card-shake')),
                cardAnimationName: cardStyle?.animationName || null,
                cardAnimationDuration: cardStyle?.animationDuration || null,
                cardAnimationActive: Boolean(cardStyle && cardStyle.animationName && cardStyle.animationName !== 'none'),
            };
        }

        // KPI Card validation: measure padding, icon size, height consistency,
        // and dashboard-specific icon color/alignment consistency.
        const kpiCards = Array.from(document.querySelectorAll('.wb-kpi-card'))
            .filter((el) => isVisible(el))
            .map((card) => {
                const body = card.querySelector('.card-body');
                const icon = card.querySelector('.wb-kpi-icon, .dashboard-stat-icon, .dns-stat-icon');

                const bodyStyle = body ? window.getComputedStyle(body) : null;
                const iconRect = icon ? icon.getBoundingClientRect() : null;

                return {
                    paddingTop: bodyStyle ? Number.parseFloat(bodyStyle.paddingTop) : null,
                    paddingBottom: bodyStyle ? Number.parseFloat(bodyStyle.paddingBottom) : null,
                    paddingLeft: bodyStyle ? Number.parseFloat(bodyStyle.paddingLeft) : null,
                    paddingRight: bodyStyle ? Number.parseFloat(bodyStyle.paddingRight) : null,
                    iconSize: iconRect ? round(iconRect.height) : null,
                };
            });

        const dashboardKpiIcons = scope === 'dashboard'
            ? Array.from(document.querySelectorAll('.dashboard-kpi-grid .wb-kpi-card'))
                .filter((el) => isVisible(el))
                .map((card) => {
                    const body = card.querySelector('.card-body');
                    const icon = card.querySelector('.wb-kpi-icon');
                    const label = card.querySelector('.wb-kpi-label');
                    const bodyRect = body?.getBoundingClientRect() || null;
                    const iconRect = icon?.getBoundingClientRect() || null;
                    const iconStyle = icon ? window.getComputedStyle(icon) : null;
                    const labelStyle = label ? window.getComputedStyle(label) : null;
                    const iconColor = iconStyle?.color || '';
                    const labelColor = labelStyle?.color || '';
                    const iconColorParsed = parseColor(iconColor);
                    const labelColorParsed = parseColor(labelColor);
                    const delta = colorDistance(iconColorParsed, labelColorParsed);
                    const iconCenter = iconRect ? (iconRect.top + iconRect.bottom) / 2 : null;
                    const bodyCenter = bodyRect ? (bodyRect.top + bodyRect.bottom) / 2 : null;
                    return {
                        label: norm(label?.textContent) || null,
                        iconName: norm(icon?.textContent) || null,
                        iconColor: normalizeColor(iconColor),
                        labelColor: normalizeColor(labelColor),
                        iconColorDelta: delta == null ? null : round(delta),
                        iconCenterDelta: iconCenter == null || bodyCenter == null ? null : round(Math.abs(iconCenter - bodyCenter)),
                        contextualClasses: Array.from(icon?.classList || [])
                            .filter((cls) => constants.KPI_CONTEXTUAL_ICON_CLASSES.includes(cls)),
                    };
                })
            : [];

        const kpiHeights = Array.from(document.querySelectorAll('.wb-kpi-card'))
            .filter((el) => isVisible(el))
            .map((card) => {
                const rect = card.getBoundingClientRect();
                return round(rect.height);
            });

        const kpiHeightVariance =
            kpiHeights.length > 1
                ? Math.max(...kpiHeights) - Math.min(...kpiHeights)
                : 0;

        const cardsWithoutKpiClass = Array.from(document.querySelectorAll('.card'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .filter((card) => {
                if (card.classList.contains('wb-kpi-card')) return false;

                // Only check stat-card candidates
                const hasIcon =
                    card.querySelector('.material-icons') ||
                    card.querySelector('.wb-kpi-icon') ||
                    card.querySelector('.dns-stat-icon') ||
                    card.querySelector('.dashboard-stat-icon');

                const hasLargeValue =
                    card.querySelector('.h3') ||
                    card.querySelector('.dns-stat-value') ||
                    card.querySelector('.wb-kpi-value');

                return hasIcon && hasLargeValue;
            })
            .slice(0, 10)
            .map(rectInfo);

        spacing.kpiCards = kpiCards;
        spacing.dashboardKpiIcons = dashboardKpiIcons;
        spacing.kpiHeights = kpiHeights;
        spacing.kpiHeightVariance = kpiHeightVariance;
        spacing.cardsMissingKpiClass = cardsWithoutKpiClass;

        // Card border-radius consistency: all .card elements should use --wb-radius-lg (12px)
        const cardBorderRadiusIssues = Array.from(document.querySelectorAll('.card'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .map((card) => {
                const style = window.getComputedStyle(card);
                const radius = Number.parseFloat(style.borderTopLeftRadius || '0');
                if (Math.abs(radius - constants.CARD_BORDER_RADIUS_EXPECTED_PX) <= constants.CARD_BORDER_RADIUS_TOLERANCE_PX) return null;
                return {
                    ...rectInfo(card),
                    radius: round(radius),
                    expected: constants.CARD_BORDER_RADIUS_EXPECTED_PX,
                };
            })
            .filter(Boolean)
            .slice(0, 10);

        spacing.cardBorderRadiusIssues = cardBorderRadiusIssues;

        // DNS page: Chart empty state spacing validation
        // Validate that "DNS Unavailable" and "Unbound is not installed." have minimal gap
        if (scope === 'dns') {
            const chartEmptyStates = Array.from(document.querySelectorAll('.chart-empty-state'))
                .filter((el) => isVisible(el) && isInContentRoot(el));

            const dnsUnavailableStates = chartEmptyStates
                .filter((state) => {
                    const textSpans = Array.from(state.querySelectorAll('.chart-empty-state-text'));
                    return textSpans.some((span) => norm(span.textContent).includes('DNS Unavailable'));
                })
                .map((state) => {
                    const icon = state.querySelector('.material-icons');
                    const textSpans = Array.from(state.querySelectorAll('.chart-empty-state-text'));
                    const mainText = textSpans.find((span) => !span.classList.contains('small'));
                    const subText = textSpans.find((span) => span.classList.contains('small'));

                    const stateStyle = window.getComputedStyle(state);
                    const gap = Number.parseFloat(stateStyle.gap || '0');

                    const subTextStyle = subText ? window.getComputedStyle(subText) : null;
                    const marginTop = subTextStyle ? Number.parseFloat(subTextStyle.marginTop || '0') : 0;

                    // Calculate visual spacing between mainText and subText
                    let visualGap = null;
                    if (mainText && subText) {
                        const mainRect = mainText.getBoundingClientRect();
                        const subRect = subText.getBoundingClientRect();
                        visualGap = round(subRect.top - mainRect.bottom);
                    }

                    return {
                        id: state.id || null,
                        hasIcon: Boolean(icon),
                        hasMainText: Boolean(mainText),
                        hasSubText: Boolean(subText),
                        hasSmallClass: Boolean(subText?.classList.contains('small')),
                        gap: round(gap),
                        marginTop: round(marginTop),
                        visualGap,
                        // Expected: negative margin-top to compensate gap (should be close to -gap)
                        marginCompensatesGap: marginTop < 0 && Math.abs(marginTop + gap) <= 2,
                        visualGapExpected: visualGap !== null && Math.abs(visualGap) <= 3,
                    };
                });

            spacing.dnsUnavailableStates = dnsUnavailableStates;

            if (window.matchMedia('(max-width: 575.98px)').matches) {
                const quickfilters = document.querySelector('.dns-quickfilters');
                const peerFilter = document.getElementById('peer-filter');
                const rangeFilter = document.getElementById('dns-range');

                if (
                    quickfilters
                    && peerFilter
                    && rangeFilter
                    && isVisible(quickfilters)
                    && isVisible(peerFilter)
                    && isVisible(rangeFilter)
                ) {
                    const peerRect = peerFilter.getBoundingClientRect();
                    const rangeRect = rangeFilter.getBoundingClientRect();
                    const topDelta = round(Math.abs(peerRect.top - rangeRect.top));
                    const bottomDelta = round(Math.abs(peerRect.bottom - rangeRect.bottom));
                    const sameRow = topDelta <= 4 && bottomDelta <= 4;
                    const widthDelta = round(Math.abs(peerRect.width - rangeRect.width));
                    const equalWidth = widthDelta <= 2;

                    spacing.dnsMobileQuickfilters = {
                        quickfilters: rectInfo(quickfilters),
                        peerFilter: rectInfo(peerFilter),
                        rangeFilter: rectInfo(rangeFilter),
                        topDelta,
                        bottomDelta,
                        sameRow,
                        widthDelta,
                        equalWidth,
                    };
                }

                // Check log filters are in same row
                const logFilter = document.getElementById('log-filter');
                const logSearch = document.getElementById('log-search');

                if (
                    logFilter
                    && logSearch
                    && isVisible(logFilter)
                    && isVisible(logSearch)
                ) {
                    const logFilterRect = logFilter.getBoundingClientRect();
                    const logSearchRect = logSearch.getBoundingClientRect();
                    const logTopDelta = round(Math.abs(logFilterRect.top - logSearchRect.top));
                    const logBottomDelta = round(Math.abs(logFilterRect.bottom - logSearchRect.bottom));
                    const logSameRow = logTopDelta <= 4 && logBottomDelta <= 4;
                    const widthDelta = round(Math.abs(logFilterRect.width - logSearchRect.width));
                    const equalWidth = widthDelta <= 2;

                    spacing.dnsMobileLogFilters = {
                        logFilter: rectInfo(logFilter),
                        logSearch: rectInfo(logSearch),
                        topDelta: logTopDelta,
                        bottomDelta: logBottomDelta,
                        sameRow: logSameRow,
                        widthDelta,
                        equalWidth,
                    };
                }
            }

            const logCardBody = document.querySelector('.log-card-body');
            const logTableWrap = document.getElementById('log-table-wrap');
            if (logCardBody && logTableWrap && isVisible(logCardBody) && isVisible(logTableWrap)) {
                const bodyStyle = window.getComputedStyle(logCardBody);
                const wrapStyle = window.getComputedStyle(logTableWrap);
                const logUnavailable = document.getElementById('log-unavailable');
                const unavailableStyle = logUnavailable ? window.getComputedStyle(logUnavailable) : null;
                const bodyRect = logCardBody.getBoundingClientRect();
                const wrapRect = logTableWrap.getBoundingClientRect();
                const bodyMinHeight = Number.parseFloat(bodyStyle.minHeight || '0');
                const wrapMinHeight = Number.parseFloat(wrapStyle.minHeight || '0');
                const bodyFlexGrow = Number.parseFloat(bodyStyle.flexGrow || '0');
                const wrapFlexGrow = Number.parseFloat(wrapStyle.flexGrow || '0');
                const rowCount = logTableWrap.querySelectorAll('#log-body > tr').length;
                const firstRow = logTableWrap.querySelector('#log-body > tr');
                const firstRowRect = firstRow ? firstRow.getBoundingClientRect() : null;
                const wrapClientHeight = logTableWrap.clientHeight;
                const wrapScrollHeight = logTableWrap.scrollHeight;
                const rowsStartBelowViewport = Boolean(firstRowRect && firstRowRect.top > wrapRect.bottom + 1);
                const wrapViewportCollapsedWithRows = rowCount > 0
                    && wrapClientHeight < constants.GHOST_SCROLL_MIN_HEIGHT_PX
                    && wrapScrollHeight > wrapClientHeight + 1;
                const bodyClipsOverflow = bodyStyle.overflowY === 'hidden' || bodyStyle.overflowY === 'clip';
                const bodyAllowsUnavailableOverlay = Boolean(
                    logUnavailable
                    && unavailableStyle
                    && bodyStyle.overflowY === 'visible'
                    && unavailableStyle.position === 'absolute'
                    && unavailableStyle.top === '0px'
                    && unavailableStyle.left === '0px'
                );

                spacing.dnsLogScrollLayout = {
                    body: rectInfo(logCardBody),
                    wrap: rectInfo(logTableWrap),
                    firstRow: firstRow ? rectInfo(firstRow) : null,
                    bodyMinHeight: round(bodyMinHeight),
                    wrapMinHeight: round(wrapMinHeight),
                    bodyFlexGrow: round(bodyFlexGrow),
                    wrapFlexGrow: round(wrapFlexGrow),
                    bodyOverflowX: bodyStyle.overflowX,
                    bodyOverflowY: bodyStyle.overflowY,
                    wrapOverflowY: wrapStyle.overflowY,
                    bodyMinHeightAllowsShrink: bodyMinHeight <= constants.FLEX_MIN_HEIGHT_ZERO_TOLERANCE_PX,
                    wrapMinHeightAllowsShrink: wrapMinHeight <= constants.FLEX_MIN_HEIGHT_ZERO_TOLERANCE_PX,
                    bodyActsAsFlexChild: bodyFlexGrow > 0,
                    wrapActsAsFlexChild: wrapFlexGrow > 0,
                    bodyClipsOverflow,
                    bodyAllowsUnavailableOverlay,
                    bodyOverflowModeSupported: bodyClipsOverflow || bodyAllowsUnavailableOverlay,
                    wrapScrollsInternally: wrapStyle.overflowY === 'auto' || wrapStyle.overflowY === 'scroll',
                    wrapFitsBody: wrapRect.height <= bodyRect.height + 1,
                    rowCount,
                    clientHeight: round(wrapClientHeight),
                    scrollHeight: round(wrapScrollHeight),
                    scrollNeeded: wrapScrollHeight > wrapClientHeight + 1,
                    wrapViewportCollapsedWithRows,
                    rowsStartBelowViewport,
                };
            }

            // DNS desktop column height alignment (Query Log ↔ Blockrate Trend)
            // Both columns should have equal height when flexbox is working correctly
            if (window.matchMedia('(min-width: 992px)').matches) {
                const mainGridCols = Array.from(document.querySelectorAll('.wb-main-grid > .col-lg-6'))
                    .filter((el) => isVisible(el));
                if (mainGridCols.length === 2) {
                    const heights = mainGridCols.map((col) => round(col.getBoundingClientRect().height));
                    const colStyles = mainGridCols.map((col) => {
                        const style = window.getComputedStyle(col);
                        return {
                            display: style.display,
                            hasDFlex: col.classList.contains('d-flex'),
                        };
                    });
                    const cards = mainGridCols.map((col) => col.querySelector('.card'));
                    const cardStyles = cards.map((card) => {
                        if (!card) return null;
                        const style = window.getComputedStyle(card);
                        return {
                            hasH100: card.classList.contains('h-100'),
                            hasFlexGrow1: card.classList.contains('flex-grow-1'),
                            flexGrow: Number.parseFloat(style.flexGrow || '0'),
                        };
                    });
                    spacing.dnsDesktopColumnAlignment = {
                        heights,
                        variance: round(Math.abs(heights[0] - heights[1])),
                        aligned: Math.abs(heights[0] - heights[1]) <= 4,
                        colStyles,
                        cardStyles,
                        // Structural requirements for flex height propagation
                        leftColHasDFlex: colStyles[0]?.hasDFlex ?? false,
                        rightColHasDFlex: colStyles[1]?.hasDFlex ?? false,
                        leftCardHasH100: cardStyles[0]?.hasH100 ?? false,
                        rightCardHasH100: cardStyles[1]?.hasH100 ?? false,
                        leftCardHasFlexGrow: (cardStyles[0]?.flexGrow ?? 0) > 0,
                        rightCardHasFlexGrow: (cardStyles[1]?.flexGrow ?? 0) > 0,
                    };
                }
            }
        }

        // Visual containment issues: detect rendering problems in rounded cards
        const visualContainmentIssues = [];
        for (const card of document.querySelectorAll('.card')) {
            if (!isVisible(card) || !isInContentRoot(card)) continue;

            const cardStyle = window.getComputedStyle(card);
            const radius = Number.parseFloat(cardStyle.borderTopLeftRadius || '0');

            if (radius <= 0) continue;

            const cardRect = card.getBoundingClientRect();
            const cardOverflow = cardStyle.overflow;
            const clipsRoundedContent = cardOverflow === 'hidden' || cardOverflow === 'clip';

            for (const child of Array.from(card.children)) {
                const childStyle = window.getComputedStyle(child);

                // Check for scroll containers without clipping
                const isScrollContainer = childStyle.overflowY === 'auto' || childStyle.overflowY === 'scroll';
                if (isScrollContainer && !clipsRoundedContent) {
                    visualContainmentIssues.push({
                        type: 'scrollContainerWithoutClipping',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }

                // Check for children overflowing card bounds
                const childRect = child.getBoundingClientRect();
                if (
                    childRect.left < cardRect.left - 1 ||
                    childRect.right > cardRect.right + 1 ||
                    childRect.bottom > cardRect.bottom + 1
                ) {
                    visualContainmentIssues.push({
                        type: 'childOverflowingRoundedCard',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }

                // Check for sticky elements inside rounded cards
                if (childStyle.position === 'sticky' || childStyle.position === '-webkit-sticky') {
                    visualContainmentIssues.push({
                        type: 'stickyElementInsideRoundedCard',
                        card: rectInfo(card),
                        child: rectInfo(child),
                    });
                }
            }
        }

        // Form-switch margin consistency: expect mb-2 (12px) for proper card spacing
        // Exception: switches in mb-3 wrappers (no direct margin) are also valid
        const FORM_SWITCH_EXPECTED_MARGIN_PX = 12;
        const FORM_SWITCH_MARGIN_TOLERANCE_PX = 2;
        const formSwitchMarginIssues = Array.from(contentRoot.querySelectorAll('.form-check.form-switch'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .map((el) => {
                const style = window.getComputedStyle(el);
                const marginBottom = Number.parseFloat(style.marginBottom || '0');
                const hasMb0 = el.classList.contains('mb-0');
                const hasMb2 = el.classList.contains('mb-2');
                const marginOk = Math.abs(marginBottom - FORM_SWITCH_EXPECTED_MARGIN_PX) <= FORM_SWITCH_MARGIN_TOLERANCE_PX;

                // Check if switch is in an mb-3 wrapper (valid pattern)
                const parentHasMb3 = el.parentElement?.classList.contains('mb-3');
                const isInMb3Wrapper = parentHasMb3 && marginBottom <= FORM_SWITCH_MARGIN_TOLERANCE_PX;

                // Valid patterns: mb-2 on switch, mb-0 on switch, or switch in mb-3 wrapper
                if (marginOk || hasMb0 || isInMb3Wrapper) return null;

                return {
                    ...rectInfo(el),
                    marginBottom: round(marginBottom),
                    hasMb0,
                    hasMb2,
                    parentHasMb3,
                    label: el.querySelector('.form-check-label')?.textContent?.trim().slice(0, 40) || null,
                };
            })
            .filter(Boolean);

        // Form-switch proportion check: toggles must not be square (width > height, min 44px)
        const FORM_SWITCH_MIN_WIDTH_PX = 44;
        const formSwitchProportionIssues = Array.from(contentRoot.querySelectorAll('.form-switch .form-check-input'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .map((el) => {
                const rect = el.getBoundingClientRect();
                const width = rect.width;
                const height = rect.height;
                const isSquare = Math.abs(width - height) < 4; // tolerance for minor rounding
                const tooNarrow = width < FORM_SWITCH_MIN_WIDTH_PX;

                if (!isSquare && !tooNarrow) return null;

                const parent = el.closest('.form-switch');
                return {
                    ...rectInfo(el),
                    width: round(width),
                    height: round(height),
                    isSquare,
                    tooNarrow,
                    label: parent?.querySelector('.form-check-label')?.textContent?.trim().slice(0, 40) || null,
                };
            })
            .filter(Boolean);

        // Form-switch height consistency: toggles should stay slightly flatter
        // than the default checkbox sizing while keeping the wider switch width.
        const formSwitchHeightIssues = Array.from(contentRoot.querySelectorAll('.form-switch .form-check-input'))
            .filter((el) => isVisible(el) && isInContentRoot(el))
            .map((el) => {
                const rect = el.getBoundingClientRect();
                const height = rect.height;
                const tooTall = height > (constants.FORM_SWITCH_MAX_HEIGHT_PX + constants.FORM_SWITCH_HEIGHT_TOLERANCE_PX);

                if (!tooTall) return null;

                const parent = el.closest('.form-switch');
                return {
                    ...rectInfo(el),
                    height: round(height),
                    maxHeight: constants.FORM_SWITCH_MAX_HEIGHT_PX,
                    tolerance: constants.FORM_SWITCH_HEIGHT_TOLERANCE_PX,
                    label: parent?.querySelector('.form-check-label')?.textContent?.trim().slice(0, 40) || null,
                };
            })
            .filter(Boolean);

        // Input-group height consistency: all children must have matching heights
        // and the group height should be close to the expected form-control height (~34px)
        const inputGroupHeightIssues = Array.from(contentRoot.querySelectorAll('.input-group'))
            .filter((group) => isVisible(group) && isInContentRoot(group))
            .map((group) => {
                const children = Array.from(group.children).filter((el) => isVisible(el));
                if (children.length < 2) return null;

                const heights = children.map((el) => {
                    const rect = el.getBoundingClientRect();
                    return round(rect.height);
                });

                const minHeight = Math.min(...heights);
                const maxHeight = Math.max(...heights);
                const heightVariance = maxHeight - minHeight;
                const avgHeight = heights.reduce((a, b) => a + b, 0) / heights.length;
                const expectedDeviation = Math.abs(avgHeight - constants.INPUT_GROUP_HEIGHT_EXPECTED_PX);

                // Issue if: children don't match OR height deviates from expected
                const hasVarianceIssue = heightVariance > constants.INPUT_GROUP_HEIGHT_TOLERANCE_PX;
                const hasExpectedHeightIssue = expectedDeviation > constants.INPUT_GROUP_HEIGHT_TOLERANCE_PX;

                if (!hasVarianceIssue && !hasExpectedHeightIssue) return null;

                return {
                    ...rectInfo(group),
                    heights,
                    minHeight,
                    maxHeight,
                    avgHeight: round(avgHeight),
                    expectedHeight: constants.INPUT_GROUP_HEIGHT_EXPECTED_PX,
                    heightVariance,
                    expectedDeviation: round(expectedDeviation),
                    issues: [
                        hasVarianceIssue && 'childHeightMismatch',
                        hasExpectedHeightIssue && 'unexpectedGroupHeight',
                    ].filter(Boolean),
                    childCount: children.length,
                    childInfo: children.map((el) => ({
                        tag: el.tagName,
                        classList: typeof el.className === 'string' ? el.className.split(' ').filter(Boolean) : [],
                        height: round(el.getBoundingClientRect().height),
                    })),
                };
            })
            .filter(Boolean);

        // Color scheme consistency: Dashboard Speedtest & Network Gauges
        // Check that Download/Upload colors match between charts for visual consistency
        const colorSchemeConsistency = (() => {
            if (scope !== 'dashboard') return null;

            const issues = [];
            const roundColor = (color) => parseColor(color);

            const colorDistance = (c1, c2) => {
                if (!c1 || !c2) return Infinity;
                return Math.sqrt(
                    Math.pow(c1.r - c2.r, 2) +
                    Math.pow(c1.g - c2.g, 2) +
                    Math.pow(c1.b - c2.b, 2)
                );
            };

            // Get gauge colors (RX = Download, TX = Upload)
            const gaugeRxColor = document.querySelector('.network-item .rx, .network-gauge-rate.rx');
            const gaugeTxColor = document.querySelector('.network-item .tx, .network-gauge-rate.tx');

            if (!gaugeRxColor || !gaugeTxColor) {
                issues.push({
                    type: 'missingGaugeElements',
                    message: 'Network gauge elements not found on dashboard'
                });
                return issues.length ? issues : null;
            }

            const gaugeRxStyle = window.getComputedStyle(gaugeRxColor);
            const gaugeTxStyle = window.getComputedStyle(gaugeTxColor);
            const gaugeRxColorParsed = roundColor(gaugeRxStyle.color);
            const gaugeTxColorParsed = roundColor(gaugeTxStyle.color);

            // Check if speedtest chart exists and has datasets
            const speedtestCanvas = document.getElementById('speedtest-chart');
            if (!speedtestCanvas) {
                // Chart not visible yet - skip check
                return null;
            }

            // Try to access Chart.js instance
            const chartInstance = speedtestCanvas && typeof Chart !== 'undefined' ? Chart.getChart(speedtestCanvas) : null;
            if (!chartInstance || !chartInstance.data.datasets || chartInstance.data.datasets.length < 2) {
                // No data yet - skip check
                return null;
            }

            // Get Download (index 0) and Upload (index 1) dataset colors
            const downloadDataset = chartInstance.data.datasets[0];
            const uploadDataset = chartInstance.data.datasets[1];

            const downloadColor = roundColor(downloadDataset.borderColor);
            const uploadColor = roundColor(uploadDataset.borderColor);

            // Compare colors (allow small RGB delta for rounding differences)
            const TOLERATED_COLOR_DISTANCE = 15; // RGB distance threshold

            const downloadDistance = colorDistance(gaugeRxColorParsed, downloadColor);
            const uploadDistance = colorDistance(gaugeTxColorParsed, uploadColor);
            const transferDistance = colorDistance(gaugeRxColorParsed, gaugeTxColorParsed);

            if (downloadDistance > TOLERATED_COLOR_DISTANCE) {
                issues.push({
                    type: 'downloadColorMismatch',
                    gaugeColor: gaugeRxStyle.color,
                    chartColor: downloadDataset.borderColor,
                    distance: Math.round(downloadDistance)
                });
            }

            if (uploadDistance > TOLERATED_COLOR_DISTANCE) {
                issues.push({
                    type: 'uploadColorMismatch',
                    gaugeColor: gaugeTxStyle.color,
                    chartColor: uploadDataset.borderColor,
                    distance: Math.round(uploadDistance)
                });
            }

            if (transferDistance < constants.DASHBOARD_TRANSFER_COLOR_DISTANCE_MIN) {
                issues.push({
                    type: 'transferColorsTooSimilar',
                    rxColor: gaugeRxStyle.color,
                    txColor: gaugeTxStyle.color,
                    distance: Math.round(transferDistance)
                });
            }

            return issues.length ? issues : null;
        })();

        // Deprecated red color validation: ensure deprecated reds are not used
        // Only approved red is #ff6384 (rgb(255, 99, 132))
        // Deprecated reds: #ff6b6b (rgb(255, 107, 107)), #ff9cab (rgb(255, 156, 171))
        const deprecatedColorUsage = (() => {
            const issues = [];
            const DEPRECATED_REDS = [
                { r: 255, g: 107, b: 107 }, // #ff6b6b
                { r: 255, g: 156, b: 171 }, // #ff9cab
            ];
            const TOLERANCE = 3; // Allow small rounding differences

            const isDeprecatedRed = (color) => {
                if (!color) return false;
                return DEPRECATED_REDS.some((deprecated) =>
                    Math.abs(color.r - deprecated.r) <= TOLERANCE &&
                    Math.abs(color.g - deprecated.g) <= TOLERANCE &&
                    Math.abs(color.b - deprecated.b) <= TOLERANCE
                );
            };

            const checkElement = (el, property, propertyName) => {
                try {
                    const style = window.getComputedStyle(el);
                    const colorValue = style[property];
                    if (!colorValue) return;

                    const color = parseColor(colorValue);
                    if (!color) return;

                    if (isDeprecatedRed(color)) {
                        issues.push({
                            element: rectInfo(el),
                            property: propertyName,
                            value: colorValue,
                            expected: 'rgb(255, 99, 132) or #ff6384',
                            selector: el.className ? `.${Array.from(el.classList).join('.')}` : el.tagName
                        });
                    }
                } catch (e) {
                    // Ignore elements that can't be inspected
                }
            };

            // Check all visible elements for deprecated color usage
            const allElements = contentElements
                .filter((el) => isVisible(el) && isInContentRoot(el));

            for (const el of allElements) {
                checkElement(el, 'color', 'color');
                checkElement(el, 'backgroundColor', 'background-color');
                checkElement(el, 'borderTopColor', 'border-color');
                checkElement(el, 'borderBottomColor', 'border-color');
                checkElement(el, 'borderLeftColor', 'border-color');
                checkElement(el, 'borderRightColor', 'border-color');
            }

            return issues.length ? issues : null;
        })();

        colorProbe.remove();

        return {
            duplicateIds,
            emptyAriaLabels,
            imgsWithoutAlt,
            emptyAltInteractive,
            unlabeledControls,
            namelessButtons,
            headingSkips,
            tablesWithoutHeaders,
            tableCellOverlapIssues,
            tablesWithoutResponsive,
            ghostScroll,
            ghostScrollContainers,
            doubleScrollRisk,
            horizontalOverflow,
            clippedButtons,
            clickTargetsTooSmall,
            iconButtonsTouchBlocked,
            deprecatedButtonClasses,
            hiddenInteractiveElements,
            bootstrapGridIssues,
            bootstrapColumnsOutsideRows,
            breakpointDisplayConflicts,
            navbarCollapseIssues,
            focusOrderIssues,
            focusIndicatorMissing,
            scrollEdgeCrowding,
            scrollBottomCrowding,
            nestedScrollContainers,
            flexScrollTraps,
            badgeStyleMismatches,
            monospaceToneMismatches,
            layoutShift,
            componentLayoutShift,
            contrastProblems,
            cardContainment,
            spacing,
            loginFailure,
            modalBackdrop,
            visualContainmentIssues,
            formSwitchMarginIssues,
            formSwitchProportionIssues,
            formSwitchHeightIssues,
            inputGroupHeightIssues,
            colorSchemeConsistency,
            deprecatedColorUsage,
        };
    }, { scope, constants: UI_EVAL_CONSTANTS });
}

async function runNodesDynamicChecks(page, view) {
    const result = {
        available: false,
        rowCount: 0,
        statusRefresh: { attempted: false, passed: false, reason: 'not-run' },
        speedtestLock: { attempted: false, passed: false, reason: 'not-run' },
    };

    const testPage = await page.context().newPage();

    const getPathname = (url) => {
        try {
            return new URL(url).pathname;
        } catch {
            return '';
        }
    };

    const statusLabel = (status) => {
        if (status === 'online') return 'Online';
        if (status === 'pending') return 'Pending';
        if (status === 'offline') return 'Offline';
        if (status === 'restarting') return 'Restarting…';
        return status || '—';
    };

    try {
        await testPage.goto(`${BASE_URL}${view.url}`, { waitUntil: 'networkidle', timeout: 30000 });
        await disableMotion(testPage, FULL_MOTION_RESET_CSS, `${view.name}-nodes-dynamic`);
        await testPage.waitForTimeout(SCREENSHOT_SETTLE_MS);

        const initialState = await testPage.evaluate(() => {
            const rows = Array.from(document.querySelectorAll('.nodes-table tbody tr[id^="node-row-"]'));
            return {
                rowCount: rows.length,
                nodes: rows.map((row) => {
                    const speedtestButton = row.querySelector('button[data-action="run-speedtest"]');
                    const statusBadge = row.querySelector('td[data-label="Status"] .node-status-badge');
                    return {
                        nodeId: row.id.replace(/^node-row-/, ''),
                        statusRaw: row.dataset.nodeStatus || speedtestButton?.dataset.nodeStatus || '',
                        statusText: statusBadge?.textContent?.trim() || '',
                        lastSpeedtestTs: row.dataset.lastSpeedtestTs || '',
                        speedtestButton: speedtestButton ? {
                            disabled: speedtestButton.disabled,
                            title: speedtestButton.getAttribute('data-bs-title') || '',
                        } : null,
                    };
                }),
            };
        });

        result.rowCount = initialState.rowCount;
        if (!initialState.rowCount) {
            result.statusRefresh.reason = 'noRows';
            result.speedtestLock.reason = 'noRows';
            return result;
        }

        result.available = true;

        const speedtestCandidate = initialState.nodes.find((node) => node.speedtestButton && node.statusRaw === 'online');
        if (speedtestCandidate) {
            result.speedtestLock.attempted = true;

            let historyMode = 'locked';
            const completionTs = new Date(Date.now() + 60_000).toISOString();
            const speedtestPath = `/api/nodes/${speedtestCandidate.nodeId}/speedtest`;
            const speedtestNodesPath = '/api/wireguard/speedtest/nodes';

            const speedtestStartHandler = async (route) => {
                if (route.request().method() !== 'POST' || getPathname(route.request().url()) !== speedtestPath) {
                    await route.continue();
                    return;
                }

                await route.fulfill({
                    status: 200,
                    contentType: 'application/json',
                    body: JSON.stringify({ status: 'ok', data: {} }),
                });
            };

            const speedtestHistoryHandler = async (route) => {
                if (route.request().method() !== 'GET' || getPathname(route.request().url()) !== speedtestNodesPath) {
                    await route.continue();
                    return;
                }

                const response = await route.fetch();
                const payload = await response.json();
                const data = payload && typeof payload === 'object' ? payload.data || {} : {};
                const nodes = Array.isArray(data.nodes) ? data.nodes : [];
                const mutatedNodes = nodes.map((entry) => {
                    if (String(entry?.node_id || '') !== speedtestCandidate.nodeId) return entry;
                    const lastSpeedtest = historyMode === 'complete'
                        ? {
                            ...(entry.last_speedtest || {}),
                            ts: completionTs,
                            node_id: speedtestCandidate.nodeId,
                            status: 'ok',
                            download_mbit: 100,
                            upload_mbit: 50,
                        }
                        : (speedtestCandidate.lastSpeedtestTs
                            ? { ...(entry.last_speedtest || {}), ts: speedtestCandidate.lastSpeedtestTs }
                            : null);
                    return {
                        ...entry,
                        status: 'online',
                        last_speedtest: lastSpeedtest,
                    };
                });

                await route.fulfill({
                    response,
                    contentType: 'application/json',
                    body: JSON.stringify({
                        ...payload,
                        data: {
                            ...data,
                            nodes: mutatedNodes,
                        },
                    }),
                });
            };

            await testPage.route(`**${speedtestPath}`, speedtestStartHandler);
            await testPage.route(`**${speedtestNodesPath}`, speedtestHistoryHandler);

            try {
                const startResponsePromise = testPage.waitForResponse((response) =>
                    response.request().method() === 'POST' && getPathname(response.url()) === speedtestPath,
                    { timeout: 5000 }
                ).catch(() => null);

                const firstHistoryPromise = testPage.waitForResponse((response) =>
                    response.request().method() === 'GET' && getPathname(response.url()) === speedtestNodesPath,
                    { timeout: 5000 }
                ).catch(() => null);

                await testPage.click(`#node-row-${speedtestCandidate.nodeId} button[data-action="run-speedtest"]`);
                await Promise.all([startResponsePromise, firstHistoryPromise]);

                const lockedApplied = await testPage.waitForFunction((nodeId) => {
                    const button = document.querySelector(`#node-row-${CSS.escape(nodeId)} button[data-action="run-speedtest"]`);
                    return Boolean(
                        button
                        && button.disabled
                        && button.classList.contains('btn-secondary')
                        && button.getAttribute('aria-busy') === 'true'
                    );
                }, speedtestCandidate.nodeId, { timeout: 5000 }).then(() => true).catch(() => false);

                historyMode = 'complete';
                const secondHistoryPromise = testPage.waitForResponse((response) =>
                    response.request().method() === 'GET' && getPathname(response.url()) === speedtestNodesPath,
                    { timeout: 5000 }
                ).catch(() => null);

                await testPage.evaluate(() => {
                    document.dispatchEvent(new Event('visibilitychange'));
                });
                await secondHistoryPromise;

                const unlockedAfterCompletion = await testPage.waitForFunction((nodeId) => {
                    const button = document.querySelector(`#node-row-${CSS.escape(nodeId)} button[data-action="run-speedtest"]`);
                    return Boolean(
                        button
                        && !button.disabled
                        && button.classList.contains('btn-outline-secondary')
                        && button.getAttribute('aria-busy') === 'false'
                    );
                }, speedtestCandidate.nodeId, { timeout: 5000 }).then(() => true).catch(() => false);

                const speedtestSnapshot = await testPage.evaluate((nodeId) => {
                    const button = document.querySelector(`#node-row-${CSS.escape(nodeId)} button[data-action="run-speedtest"]`);
                    return button ? {
                        disabled: button.disabled,
                        title: button.getAttribute('data-bs-title') || '',
                        ariaBusy: button.getAttribute('aria-busy') || '',
                        className: button.className,
                    } : null;
                }, speedtestCandidate.nodeId);

                result.speedtestLock = {
                    attempted: true,
                    passed: lockedApplied && unlockedAfterCompletion,
                    reason: !lockedApplied
                        ? 'lockNotApplied'
                        : !unlockedAfterCompletion
                            ? 'lockNotReleased'
                            : 'ok',
                    nodeId: speedtestCandidate.nodeId,
                    lockedApplied,
                    unlockedAfterCompletion,
                    snapshot: speedtestSnapshot,
                };
            } finally {
                await testPage.unroute(`**${speedtestPath}`, speedtestStartHandler);
                await testPage.unroute(`**${speedtestNodesPath}`, speedtestHistoryHandler);
            }
        } else {
            result.speedtestLock.reason = 'noOnlineRow';
        }

        const statusCandidate = initialState.nodes[0];
        if (statusCandidate) {
            result.statusRefresh.attempted = true;

            const desiredStatus = statusCandidate.statusRaw === 'online' ? 'offline' : 'online';
            const expectedLabel = statusLabel(desiredStatus);
            const nodesHandler = async (route) => {
                if (route.request().method() !== 'GET' || getPathname(route.request().url()) !== '/api/nodes') {
                    await route.continue();
                    return;
                }

                const response = await route.fetch();
                const payload = await response.json();
                const data = Array.isArray(payload?.data) ? payload.data : [];
                const mutatedNodes = data.map((node) => {
                    if (String(node?.id || '') !== statusCandidate.nodeId) return node;
                    return { ...node, status: desiredStatus };
                });

                await route.fulfill({
                    response,
                    contentType: 'application/json',
                    body: JSON.stringify({ ...payload, data: mutatedNodes }),
                });
            };

            await testPage.route('**/api/nodes', nodesHandler);

            try {
                const refreshResponsePromise = testPage.waitForResponse((response) =>
                    response.request().method() === 'GET' && getPathname(response.url()) === '/api/nodes',
                    { timeout: 5000 }
                ).catch(() => null);

                await testPage.evaluate(() => {
                    document.dispatchEvent(new Event('visibilitychange'));
                });
                await refreshResponsePromise;

                const badgeUpdated = await testPage.waitForFunction(({ nodeId, expectedText }) => {
                    const badge = document.querySelector(`#node-row-${CSS.escape(nodeId)} td[data-label="Status"] .node-status-badge`);
                    return badge?.textContent?.trim() === expectedText;
                }, { nodeId: statusCandidate.nodeId, expectedText: expectedLabel }, { timeout: 5000 }).then(() => true).catch(() => false);

                const statusSnapshot = await testPage.evaluate((nodeId) => {
                    const row = document.getElementById(`node-row-${nodeId}`);
                    const badge = row?.querySelector('td[data-label="Status"] .node-status-badge');
                    return {
                        rowStatus: row?.dataset.nodeStatus || '',
                        badgeText: badge?.textContent?.trim() || '',
                        badgeClass: badge?.className || '',
                    };
                }, statusCandidate.nodeId);

                result.statusRefresh = {
                    attempted: true,
                    passed: badgeUpdated,
                    reason: badgeUpdated ? 'ok' : 'badgeNotUpdated',
                    nodeId: statusCandidate.nodeId,
                    expectedLabel,
                    snapshot: statusSnapshot,
                };
            } finally {
                await testPage.unroute('**/api/nodes', nodesHandler);
            }
        }

        return result;
    } finally {
        await testPage.close().catch(() => { });
    }
}

async function auditView(page, view) {
    const detachNetwork = collectConsoleAndNetwork(page);
    let network = null;
    try {
        await applyTheme(page, { baseUrl: BASE_URL, theme: view.theme, label: view.name });
        const response = await page.goto(`${BASE_URL}${view.url}`, { waitUntil: 'networkidle', timeout: 30000 });
        await disableMotion(page, FULL_MOTION_RESET_CSS, view.name);
        if (view.scope === 'about') {
            await page.evaluate(() => {
                const details = document.querySelector('.about-changelog-col details');
                if (details) details.open = true;
            });
            await page.waitForTimeout(DETAILS_EXPAND_SETTLE_MS);
        }
        if (view.tab) {
            await page.click(view.tab);
            await page.waitForTimeout(TAB_SWITCH_SETTLE_MS);
        }
        if (view.scope === 'traffic') {
            await page.waitForFunction(() => {
                const chartLoading = document.getElementById('traffic-combined-loading');
                const countryLoading = document.getElementById('country-traffic-loading');
                const asnLoading = document.getElementById('asn-traffic-loading');
                const hidden = (el) => !el || el.classList.contains('d-none');
                return hidden(chartLoading) && hidden(countryLoading) && hidden(asnLoading);
            }, { timeout: 10000 }).catch(() => { });
        }
        await resetLayoutShiftMetric(page);
        await page.waitForTimeout(SCREENSHOT_SETTLE_MS);
        const shots = await captureStablePair(page, {
            motionResetCss: FULL_MOTION_RESET_CSS,
            name: view.name,
            screenshotDir: SCREENSHOT_DIR,
            screenshotSettleMs: SCREENSHOT_SETTLE_MS,
        });
        const kpiShots = await captureKpiCards(page, view.name, SCREENSHOT_DIR);
        const diff = diffScreenshots({
            name: view.name,
            shotA: shots.shotA,
            shotB: shots.shotB,
            screenshotDir: SCREENSHOT_DIR,
        });
        const metrics = await collectPageMetrics(page, view.scope);
        if (view.scope === 'nodes') {
            metrics.spacing.nodesDynamicBehavior = await runNodesDynamicChecks(page, view);
        }
        network = detachNetwork();
        const statusUnavailableExpected = isExpectedStatusUnavailable(view, response);
        network.requestFailures = network.requestFailures.filter((entry) => entry.error !== 'net::ERR_ABORTED');
        if (statusUnavailableExpected) {
            network.consoleEntries = network.consoleEntries.filter((entry) => {
                const text = String(entry.text || '');
                return !(text.includes('/status') && text.includes('404'))
                    && text !== 'Failed to load resource: the server responded with a status of 404 (Not Found)';
            });
            network.badResponses = network.badResponses.filter((entry) => {
                try {
                    return !(entry.status === 404 && new URL(entry.url).pathname === '/status');
                } catch {
                    return true;
                }
            });
        }
        return {
            name: view.name,
            url: page.url(),
            theme: view.theme,
            diff,
            metrics,
            network,
            statusUnavailableExpected,
            findings: [],
            screenshots: { ...shots, diffPath: diff.diffPath },
            kpiShots,
        };
    } finally {
        // Always detach network listeners to prevent memory leaks
        if (!network) detachNetwork();
    }
}

async function auditLoginFailureView(page, view) {
    const detachNetwork = collectConsoleAndNetwork(page);
    let network = null;
    try {
        await page.goto(`${BASE_URL}${view.url}`, { waitUntil: 'networkidle', timeout: 10000 });
        await disableMotion(page, FULL_MOTION_RESET_CSS, view.name);
        await applyTheme(page, { baseUrl: BASE_URL, theme: view.theme, label: view.name });

        const invalidPassword = `${PASSWORD}__ui_lint_invalid`;
        await page.fill('#username', USERNAME);
        await page.fill('#password', invalidPassword);

        const [loginResponse] = await Promise.all([
            page.waitForResponse((response) => {
                try {
                    return new URL(response.url()).pathname === '/api/login';
                } catch {
                    return false;
                }
            }, { timeout: 30000 }),
            page.click('#submit-btn'),
        ]);

        // Wait for error alert to appear (attached to DOM without d-none class)
        // Use 'attached' state since visibility can be affected by animations
        await page.waitForSelector('#error-alert:not(.d-none)', { state: 'attached', timeout: 30000 });
        await page.waitForTimeout(LOGIN_ERROR_SETTLE_MS);

        const metrics = await collectPageMetrics(page, view.scope);
        const shots = await captureStablePair(page, {
            motionResetCss: FULL_MOTION_RESET_CSS,
            name: view.name,
            screenshotDir: SCREENSHOT_DIR,
            screenshotSettleMs: SCREENSHOT_SETTLE_MS,
        });
        const kpiShots = await captureKpiCards(page, view.name, SCREENSHOT_DIR);
        const diff = diffScreenshots({
            name: view.name,
            shotA: shots.shotA,
            shotB: shots.shotB,
            screenshotDir: SCREENSHOT_DIR,
        });
        network = detachNetwork();
        network.consoleEntries = network.consoleEntries.filter((entry) =>
            !(loginResponse.status() === 401 && entry.text.includes('401 (Unauthorized)'))
        );
        network.requestFailures = network.requestFailures.filter((entry) => entry.error !== 'net::ERR_ABORTED');
        network.badResponses = network.badResponses.filter((entry) => {
            try {
                return !(entry.status === 401 && new URL(entry.url).pathname === '/api/login');
            } catch {
                return true;
            }
        });

        return {
            name: view.name,
            url: page.url(),
            theme: view.theme,
            diff,
            metrics,
            network,
            findings: [],
            screenshots: { ...shots, diffPath: diff.diffPath },
            kpiShots,
            loginResponseStatus: loginResponse.status(),
        };
    } finally {
        // Always detach network listeners to prevent memory leaks
        if (!network) detachNetwork();
    }
}

async function main() {
    // Clean up old output files
    if (fs.existsSync(OUTPUT_DIR)) {
        const files = fs.readdirSync(OUTPUT_DIR);
        for (const file of files) {
            if (file.endsWith('.png') || file.endsWith('.json')) {
                fs.unlinkSync(path.join(OUTPUT_DIR, file));
            }
        }
    }
    ensureDir(OUTPUT_DIR);
    fs.rmSync(SCREENSHOT_DIR, { recursive: true, force: true });
    ensureDir(SCREENSHOT_DIR);

    const results = [];
    let browser;

    try {
        browser = await chromium.launch({ headless: true });
        const authContext = await browser.newContext({ viewport: { width: 1440, height: 1100 } });
        await login(await authContext.newPage(), {
            baseUrl: BASE_URL,
            username: USERNAME,
            password: PASSWORD,
            motionResetCss: FULL_MOTION_RESET_CSS,
        });
        const authState = await authContext.storageState();
        await authContext.close();

        const desktopContext = await browser.newContext({
            viewport: { width: 1440, height: 1100 },
            storageState: authState,
        });
        const largeDesktopContext = await browser.newContext({
            viewport: { width: 1600, height: 1100 },
            storageState: authState,
        });
        const tabletContext = await browser.newContext({
            ...devices['iPad Pro 11'],
            storageState: authState,
        });
        const mobileContext = await browser.newContext({
            ...devices['iPhone 13'],
            storageState: authState,
        });
        await installLayoutShiftObserver(desktopContext);
        await installLayoutShiftObserver(largeDesktopContext);
        await installLayoutShiftObserver(tabletContext);
        await installLayoutShiftObserver(mobileContext);

        const desktopPage = await desktopContext.newPage();
        const largeDesktopPage = await largeDesktopContext.newPage();
        const tabletPage = await tabletContext.newPage();
        const mobilePage = await mobileContext.newPage();

        // Run authenticated view tests
        for (const view of VIEWS) {
            let page;
            if (view.device === 'mobile') {
                page = mobilePage;
            } else if (view.device === 'tablet') {
                page = tabletPage;
            } else if (view.device === 'large-desktop') {
                page = largeDesktopPage;
            } else {
                page = desktopPage;
            }
            try {
                const result = await auditView(page, view);
                const summarized = summarizeFindings(result);
                result.findings = summarized.findings;
                result.hardFindings = summarized.hardFindings;
                result.warnings = summarized.warnings;
                results.push(result);
            } catch (err) {
                console.error(`[${view.name}] Audit failed: ${err.message}`);
                results.push({
                    name: view.name,
                    url: view.url,
                    theme: view.theme,
                    error: err.message,
                    findings: ['auditError'],
                    hardFindings: ['auditError'],
                    warnings: [],
                    diff: { ratio: 0, sizeMismatch: false },
                    metrics: {},
                    network: { consoleEntries: [], pageErrors: [], requestFailures: [], badResponses: [], requests: [], duplicateRequests: [] },
                });
            }
        }

        // Run login-failure tests LAST to avoid rate limiting blocking the real login
        for (const [index, view] of LOGIN_FAILURE_VIEWS.entries()) {
            let page;
            if (view.device === 'mobile') {
                page = mobilePage;
            } else if (view.device === 'tablet') {
                page = tabletPage;
            } else if (view.device === 'large-desktop') {
                page = largeDesktopPage;
            } else {
                page = desktopPage;
            }

            // Retry logic for rate limiting: detect "too many attempts" and wait before retry
            let result;
            let attempt = 0;
            const maxRetries = 3;

            while (attempt < maxRetries) {
                try {
                    // Stagger login attempts to stay under 5/minute rate limit
                    if (index > 0 && attempt === 0) {
                        await new Promise((resolve) => setTimeout(resolve, LOGIN_TEST_STAGGER_MS));
                    }

                    result = await auditLoginFailureView(page, view);

                    // Check if rate limited by examining error text
                    const errorText = result?.metrics?.loginFailure?.errorText?.toLowerCase() || '';
                    if (errorText.includes('too many') || errorText.includes('rate limit') || errorText.includes('locked')) {
                        if (attempt < maxRetries - 1) {
                            console.warn(`[${view.name}] Rate limited, waiting ${LOGIN_LOCKOUT_RESET_MS}ms before retry ${attempt + 1}/${maxRetries - 1}`);
                            await new Promise((resolve) => setTimeout(resolve, LOGIN_LOCKOUT_RESET_MS));
                            attempt++;
                            continue;
                        }
                    }

                    // Success or non-rate-limit error
                    break;
                } catch (err) {
                    if (attempt === maxRetries - 1) {
                        console.error(`[${view.name}] Audit failed after ${maxRetries} attempts: ${err.message}`);
                        result = {
                            name: view.name,
                            url: view.url,
                            theme: view.theme,
                            error: err.message,
                            findings: ['auditError'],
                            hardFindings: ['auditError'],
                            warnings: [],
                            diff: { ratio: 0, sizeMismatch: false },
                            metrics: {},
                            network: { consoleEntries: [], pageErrors: [], requestFailures: [], badResponses: [], requests: [], duplicateRequests: [] },
                        };
                        break;
                    }
                    attempt++;
                }
            }

            if (result) {
                const summarized = summarizeFindings(result);
                result.findings = summarized.findings;
                result.hardFindings = summarized.hardFindings;
                result.warnings = summarized.warnings;
                results.push(result);
            }
        }
    } finally {
        if (browser) {
            await browser.close();
        }
    }

    const summaryPath = path.join(RESULTS_DIR, 'ui-lint-summary.json');
    fs.writeFileSync(summaryPath, JSON.stringify(results, null, 2));

    console.log(`\nResults saved to: ${summaryPath}`);
    console.log(`Screenshots: ${SCREENSHOT_DIR}\n`);

    console.log('UI_LINT_START');
    for (const result of results) {
        const metrics = result.metrics || {};
        const spacing = metrics.spacing || {};
        const horizontalOverflow = metrics.horizontalOverflow || {};
        const layoutShiftValue = Number(metrics.layoutShift?.value || 0);
        console.log(JSON.stringify({
            name: result.name,
            url: result.url,
            theme: result.theme || null,
            findings: result.findings,
            hardFindings: result.hardFindings || [],
            warnings: result.warnings || [],
            diffRatio: Number(result.diff.ratio.toFixed(6)),
            layoutShift: Number(layoutShiftValue.toFixed(6)),
            overflowOffenders: horizontalOverflow.offenders?.length || 0,
            clippedButtons: metrics.clippedButtons?.length || 0,
            clickTargetsTooSmall: metrics.clickTargetsTooSmall?.length || 0,
            iconButtonsTouchBlocked: metrics.iconButtonsTouchBlocked?.length || 0,
            hiddenInteractive: metrics.hiddenInteractiveElements?.length || 0,
            bootstrapGridIssues: metrics.bootstrapGridIssues?.length || 0,
            bootstrapColumnsOutsideRows: metrics.bootstrapColumnsOutsideRows?.length || 0,
            breakpointDisplayConflicts: metrics.breakpointDisplayConflicts?.length || 0,
            navbarCollapseIssues: metrics.navbarCollapseIssues?.length || 0,
            focusOrderIssues: metrics.focusOrderIssues?.length || 0,
            focusIndicatorMissing: metrics.focusIndicatorMissing?.length || 0,
            scrollEdgeCrowding: metrics.scrollEdgeCrowding?.length || 0,
            scrollBottomCrowding: metrics.scrollBottomCrowding?.length || 0,
            ghostScrollContainers: metrics.ghostScrollContainers?.length || 0,
            nestedScrollContainers: metrics.nestedScrollContainers?.length || 0,
            flexScrollTraps: metrics.flexScrollTraps?.length || 0,
            badgeStyleMismatches: metrics.badgeStyleMismatches?.length || 0,
            monospaceToneMismatches: metrics.monospaceToneMismatches?.length || 0,
            modalBackdropBlur: metrics.modalBackdrop?.blurPx ?? null,
            modalBackdropSaturate: metrics.modalBackdrop?.saturate ?? null,
            modalBackdropAlpha: metrics.modalBackdrop?.alpha ?? null,
            contrastProblems: metrics.contrastProblems?.length || 0,
            componentLayoutShift: metrics.componentLayoutShift?.length || 0,
            visualContainmentIssues: metrics.visualContainmentIssues?.length || 0,
            sliderAlignment: spacing.sliderAlignment?.length || 0,
            sliderTickMisaligned: spacing.sliderAlignment?.filter((s) => s.tickMisaligned?.length)?.length || 0,
            sliderLabelOverlap: spacing.sliderAlignment?.filter((s) => s.labelOverlap?.length)?.length || 0,
            mobileRowCardStackGapRows: spacing.mobileRowCardStackGaps?.length || 0,
            mobileRowCardStackGapIssues: spacing.mobileRowCardStackGaps?.filter((entry) => !entry.gapsConsistent)?.length || 0,
            settingsTabColors: spacing.settingsTabColors?.length || 0,
            settingsTabActiveColorMismatch: spacing.settingsTabColors?.filter((entry) => entry.colorDelta != null && entry.colorDelta > SETTINGS_TAB_COLOR_DISTANCE_MAX)?.length || 0,
            logsPathLayout: spacing.logsPathLayout?.length || 0,
            logsPathStyleMismatch: spacing.logsPathLayout?.filter((entry) => entry.whiteSpace !== 'nowrap' || entry.textOverflow !== 'ellipsis' || entry.overflowX !== 'hidden')?.length || 0,
            logsPathWrapped: spacing.logsPathLayout?.filter((entry) => entry.wraps)?.length || 0,
            compactCardActionRows: spacing.compactCardActionRows?.length || 0,
            compactCardActionRowIssues: spacing.compactCardActionRows?.filter((entry) => !entry.isCompactMargin || !entry.isCompactPadding || !entry.isBorderless)?.length || 0,
            duplicateRequests: result.network.duplicateRequests?.length || 0,
            kpiCards: spacing.kpiCards?.length || 0,
            dashboardKpiIcons: spacing.dashboardKpiIcons?.length || 0,
            dashboardKpiContextualIconColor: spacing.dashboardKpiIcons?.filter((card) => card.contextualClasses?.length)?.length || 0,
            dashboardKpiNeutralIconMismatch: spacing.dashboardKpiIcons?.filter((card) => card.iconColorDelta != null && card.iconColorDelta > KPI_ICON_NEUTRAL_COLOR_DISTANCE_MAX)?.length || 0,
            dashboardKpiIconVerticalCenter: spacing.dashboardKpiIcons?.filter((card) => card.iconCenterDelta != null && card.iconCenterDelta > KPI_ICON_CENTER_TOLERANCE_PX)?.length || 0,
            kpiMissingClass: spacing.cardsMissingKpiClass?.length || 0,
            cardBorderRadiusMismatch: spacing.cardBorderRadiusIssues?.length || 0,
            kpiHeightVariance: spacing.kpiHeightVariance || 0,
            dashboardTopRowVariance: spacing.dashboardTopRowAlignment?.variance || 0,
            dnsUnavailableStates: spacing.dnsUnavailableStates?.length || 0,
            dnsUnavailableIncorrectSpacing: spacing.dnsUnavailableStates?.filter(s => !s.marginCompensatesGap || !s.visualGapExpected)?.length || 0,
            dnsMobileQuickfilters: spacing.dnsMobileQuickfilters ? 1 : 0,
            dnsMobileQuickfiltersWrapped: spacing.dnsMobileQuickfilters && !spacing.dnsMobileQuickfilters.sameRow ? 1 : 0,
            dnsMobileQuickfiltersWidthMismatch: spacing.dnsMobileQuickfilters && !spacing.dnsMobileQuickfilters.equalWidth ? 1 : 0,
            dnsMobileLogFilters: spacing.dnsMobileLogFilters ? 1 : 0,
            dnsMobileLogFiltersWrapped: spacing.dnsMobileLogFilters && !spacing.dnsMobileLogFilters.sameRow ? 1 : 0,
            dnsMobileLogFiltersWidthMismatch: spacing.dnsMobileLogFilters && !spacing.dnsMobileLogFilters.equalWidth ? 1 : 0,
            dnsLogScrollLayout: spacing.dnsLogScrollLayout ? 1 : 0,
            dnsLogScrollLayoutIssues: spacing.dnsLogScrollLayout
                ? [
                    !spacing.dnsLogScrollLayout.bodyMinHeightAllowsShrink,
                    !spacing.dnsLogScrollLayout.wrapMinHeightAllowsShrink,
                    !spacing.dnsLogScrollLayout.wrapScrollsInternally,
                    spacing.dnsLogScrollLayout.wrapViewportCollapsedWithRows,
                    spacing.dnsLogScrollLayout.rowsStartBelowViewport,
                    !spacing.dnsLogScrollLayout.bodyActsAsFlexChild,
                    !spacing.dnsLogScrollLayout.wrapActsAsFlexChild,
                    !spacing.dnsLogScrollLayout.bodyOverflowModeSupported,
                    !spacing.dnsLogScrollLayout.wrapFitsBody,
                ].filter(Boolean).length
                : 0,
            dnsDesktopColumnAlignment: spacing.dnsDesktopColumnAlignment ? 1 : 0,
            dnsDesktopColumnVariance: spacing.dnsDesktopColumnAlignment?.variance || 0,
            dnsDesktopColumnAligned: spacing.dnsDesktopColumnAlignment?.aligned ? 1 : 0,
            aboutMobileTopRowStackGaps: spacing.about?.mobileTopRowStack?.gaps?.length || 0,
            aboutMobileTopRowGapVariance: spacing.about?.mobileTopRowStack?.gapVariance || 0,
            statusFlowNodes: spacing.statusFlow?.nodeCount || 0,
            statusFlowConnectors: spacing.statusFlow?.connectorCount || 0,
            statusFlowHeightVariance: spacing.statusFlow?.heightVariance || 0,
            statusCheckMonospaceCards: spacing.statusCheckMonospace?.cards?.length || 0,
            statusCheckMonospaceMissing: spacing.statusCheckMonospace?.missing?.length || 0,
            loginErrorVisible: Boolean(metrics.loginFailure?.alertVisible),
            loginShakeActive: Boolean(metrics.loginFailure?.cardAnimationActive),
            loginPasswordInvalid: Boolean(metrics.loginFailure?.passwordInvalidClass),
            summaryPath,
        }));
    }
    console.log('UI_LINT_END');

    const hasHardFindings = results.some((result) => (result.hardFindings || []).length > 0);
    process.exitCode = hasHardFindings ? 1 : 0;
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
