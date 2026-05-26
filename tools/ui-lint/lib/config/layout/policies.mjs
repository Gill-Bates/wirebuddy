//
// tools/ui-lint/lib/config/layout/policies.mjs
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

const SPACING_TOKENS = deepFreeze({
    xsPx: 4,
    smPx: 8,
    mdPx: 12,
    lgPx: 24,
    xlPx: 32,
    xxlPx: 120,
});

/**
 * Dashboard/list row gap bounds observed to produce visually stable vertical rhythm
 * across Chromium/WebKit/Firefox without creating crowded stacks on compact layouts.
 */
export const LAYOUT_SPACING_POLICY = deepFreeze(validateNumericPolicy('LAYOUT_SPACING_POLICY', {
    verticalGapMinPx: 22,
    verticalGapMaxPx: 26,
    stackGapVarianceTolerancePx: 2,
    scrollEdgeClearanceMinPx: SPACING_TOKENS.mdPx,
    ghostScrollDeltaMaxPx: SPACING_TOKENS.smPx,
    ghostScrollMinHeightPx: SPACING_TOKENS.xxlPx,
}));

if (LAYOUT_SPACING_POLICY.verticalGapMinPx > LAYOUT_SPACING_POLICY.verticalGapMaxPx) {
    throw new TypeError('LAYOUT_SPACING_POLICY.verticalGapMinPx must be <= verticalGapMaxPx');
}

export const OVERFLOW_POLICY = deepFreeze(validateNumericPolicy('OVERFLOW_POLICY', {
    warningPx: 6,
    errorPx: 24,
    criticalPx: 80,
}));

if (OVERFLOW_POLICY.warningPx > OVERFLOW_POLICY.errorPx || OVERFLOW_POLICY.errorPx > OVERFLOW_POLICY.criticalPx) {
    throw new TypeError('OVERFLOW_POLICY thresholds must be ascending: warning <= error <= critical');
}

/**
 * Acceptable subpixel rendering drift before the UI is considered unstable.
 * Derived from observed browser rounding variance during screenshot-based audits.
 */
export const LAYOUT_STABILITY_POLICY = deepFreeze(validateNumericPolicy('LAYOUT_STABILITY_POLICY', {
    visualDriftThreshold: 0.0025,
    layoutShiftThreshold: 0.02,
    componentLayoutShiftThresholdPx: 2,
    flexMinHeightZeroTolerancePx: 0.5,
}));

export const FOOTER_POLICY = deepFreeze(validateNumericPolicy('FOOTER_POLICY', {
    overlapTolerancePx: 1,
    zIndex: 1000,
}));

export const LAYOUT_POLICY = deepFreeze({
    spacing: LAYOUT_SPACING_POLICY,
    overflow: OVERFLOW_POLICY,
    stability: LAYOUT_STABILITY_POLICY,
    footer: FOOTER_POLICY,
});

export const VERTICAL_GAP_MIN = LAYOUT_SPACING_POLICY.verticalGapMinPx;
export const VERTICAL_GAP_MAX = LAYOUT_SPACING_POLICY.verticalGapMaxPx;
export const STACK_GAP_VARIANCE_TOLERANCE_PX = LAYOUT_SPACING_POLICY.stackGapVarianceTolerancePx;
export const SCROLL_EDGE_CLEARANCE_MIN = LAYOUT_SPACING_POLICY.scrollEdgeClearanceMinPx;
export const GHOST_SCROLL_DELTA_MAX_PX = LAYOUT_SPACING_POLICY.ghostScrollDeltaMaxPx;
export const GHOST_SCROLL_MIN_HEIGHT_PX = LAYOUT_SPACING_POLICY.ghostScrollMinHeightPx;

export const VISUAL_DRIFT_THRESHOLD = LAYOUT_STABILITY_POLICY.visualDriftThreshold;
export const LAYOUT_SHIFT_THRESHOLD = LAYOUT_STABILITY_POLICY.layoutShiftThreshold;
export const COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX = LAYOUT_STABILITY_POLICY.componentLayoutShiftThresholdPx;
export const FLEX_MIN_HEIGHT_ZERO_TOLERANCE_PX = LAYOUT_STABILITY_POLICY.flexMinHeightZeroTolerancePx;

export const OVERFLOW_TOLERANCE_PX = OVERFLOW_POLICY.warningPx;
export const FOOTER_OVERLAP_TOLERANCE_PX = FOOTER_POLICY.overlapTolerancePx;
export const FOOTER_Z_INDEX = FOOTER_POLICY.zIndex;