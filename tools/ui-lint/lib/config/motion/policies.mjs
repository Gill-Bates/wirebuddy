//
// tools/ui-lint/lib/config/motion/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }

    Object.freeze(value);
    for (const nested of Object.values(value)) {
        deepFreeze(nested);
    }
    return value;
}

function assertNonNegativeFiniteNumber(value, name) {
    if (!Number.isFinite(value) || value < 0) {
        throw new TypeError(`${name} must be a non-negative finite number, got ${value}`);
    }
}

function validateNumericPolicy(policyName, policy) {
    for (const [key, value] of Object.entries(policy)) {
        assertNonNegativeFiniteNumber(value, `${policyName}.${key}`);
    }
    return policy;
}

export const MOTION_SCOPE_SELECTOR = 'html[data-ui-lint-motion]';

const MOTION_DISABLE_DECLARATIONS = [
    'animation: none !important;',
    'transition: none !important;',
].join('\n    ');

function scopeSelectors(selectors) {
    return selectors
        .split(',')
        .map((selector) => selector.trim())
        .filter(Boolean)
        .map((selector) => `${MOTION_SCOPE_SELECTOR} ${selector}`)
        .join(',\n  ');
}

function createMotionReset(selectors) {
    return `@layer ui-lint-motion-reset {
  ${scopeSelectors(selectors)} {
    ${MOTION_DISABLE_DECLARATIONS}
  }
}`;
}

const BASE_MOTION_RESET_CSS = `@layer ui-lint-motion-reset {
  ${MOTION_SCOPE_SELECTOR},
  ${MOTION_SCOPE_SELECTOR} *,
  ${MOTION_SCOPE_SELECTOR} *::before,
  ${MOTION_SCOPE_SELECTOR} *::after {
    ${MOTION_DISABLE_DECLARATIONS}
    scroll-behavior: auto !important;
  }
}`;

const LEAFLET_MOTION_RESET_CSS = createMotionReset(`
  .leaflet-pane,
  .leaflet-control-container
`);

const CHARTS_MOTION_RESET_CSS = createMotionReset(`
  .chart,
  .apexcharts-canvas,
  canvas
`);

const PULSE_MARKERS_MOTION_RESET_CSS = createMotionReset(`
  .pulse-marker,
  #peer-map img,
  #peer-map canvas
`);

export const APP_MOTION_RULES = deepFreeze({
    leaflet: LEAFLET_MOTION_RESET_CSS,
    charts: CHARTS_MOTION_RESET_CSS,
    pulseMarkers: PULSE_MARKERS_MOTION_RESET_CSS,
});

const MOTION_RESET_CSS = BASE_MOTION_RESET_CSS.trim();
const APP_SPECIFIC_MOTION_RESET_CSS = Object.values(APP_MOTION_RULES).join('\n\n');

export const MOTION_POLICY = deepFreeze({
    scopeSelector: MOTION_SCOPE_SELECTOR,
    resetCss: MOTION_RESET_CSS,
    appSpecificRules: APP_MOTION_RULES,
});

export function buildMotionResetCSS({
    include = [],
    disableLeaflet = false,
    disableCharts = false,
    disablePulseMarkers = false,
} = {}) {
    const requested = new Set(include);

    // Backward-compatible aliases: existing callers set disableX=true to add that reset.
    if (disableLeaflet) requested.add('leaflet');
    if (disableCharts) requested.add('charts');
    if (disablePulseMarkers) requested.add('pulseMarkers');

    const parts = [MOTION_RESET_CSS];

    for (const key of requested) {
        const css = APP_MOTION_RULES[key];
        if (!css) {
            throw new TypeError(`Unknown motion reset target: ${key}`);
        }
        parts.push(css);
    }

    return parts.join('\n\n');
}

export const FULL_MOTION_RESET_CSS = buildMotionResetCSS({
    include: Object.keys(APP_MOTION_RULES),
});

/**
 * Maximum acceptable transition durations used by UX responsiveness checks.
 */
export const TRANSITION_POLICY = deepFreeze(validateNumericPolicy('TRANSITION_POLICY', {
    defaultMaxMs: 200,
    slowMaxMs: 300,
    fastMaxMs: 150,
}));

if (TRANSITION_POLICY.fastMaxMs > TRANSITION_POLICY.defaultMaxMs || TRANSITION_POLICY.defaultMaxMs > TRANSITION_POLICY.slowMaxMs) {
    throw new TypeError('TRANSITION_POLICY thresholds must be ordered fast <= default <= slow');
}

export { APP_SPECIFIC_MOTION_RESET_CSS, MOTION_RESET_CSS };