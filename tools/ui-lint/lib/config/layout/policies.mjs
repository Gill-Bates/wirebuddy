//
// tools/ui-lint/lib/config/layout/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const LAYOUT_SPACING_POLICY = Object.freeze({
    verticalGapMinPx: 22,
    verticalGapMaxPx: 26,
    stackGapVarianceTolerancePx: 2,
    scrollEdgeClearanceMinPx: 12,
    ghostScrollDeltaMaxPx: 8,
    ghostScrollMinHeightPx: 120,
});

export const OVERFLOW_POLICY = Object.freeze({
    warningPx: 6,
    errorPx: 24,
    criticalPx: 80,
});

export const LAYOUT_STABILITY_POLICY = Object.freeze({
    visualDriftThreshold: 0.0025,
    layoutShiftThreshold: 0.02,
    componentLayoutShiftThresholdPx: 2,
    flexMinHeightZeroTolerancePx: 0.5,
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
export const FOOTER_OVERLAP_TOLERANCE_PX = 1;