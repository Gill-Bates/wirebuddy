//
// tools/ui-lint/lib/config/runtime/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { COMPONENT_CONTRACTS, ABOUT_CONTRACT, FORM_CONTRACT, STATUS_CONTRACT } from '../components/contracts.mjs';
import { TOUCH_TARGET_POLICY } from '../accessibility/touch-targets.mjs';
import { LAYOUT_SPACING_POLICY, LAYOUT_STABILITY_POLICY, OVERFLOW_POLICY } from '../layout/policies.mjs';
import { MOTION_POLICY } from '../motion/policies.mjs';
import { SCREENSHOT_TIMING_POLICY } from '../screenshots/policies.mjs';
import { WCAG_CONTRAST } from '../accessibility/wcag.mjs';

export const BROWSER_CAPABILITIES = Object.freeze({
    chromium: Object.freeze({ supportsCLS: true, supportsINP: true, supportsLCP: true, supportsMemory: true }),
    webkit: Object.freeze({ supportsCLS: true, supportsINP: false, supportsLCP: true, supportsMemory: false }),
    firefox: Object.freeze({ supportsCLS: false, supportsINP: true, supportsLCP: true, supportsMemory: true }),
});

export const DEVICE_PROFILE_REGISTRY = Object.freeze({
    desktop: Object.freeze({ class: 'desktop', density: 'comfortable', viewportScale: 1 }),
    tablet: Object.freeze({ class: 'tablet', density: 'balanced', viewportScale: 0.85 }),
    mobile: Object.freeze({ class: 'mobile', density: 'compact', viewportScale: 0.72 }),
});

export const UI_LINT_PROFILES = Object.freeze({
    ci: Object.freeze({ settleMultiplier: 1.25, motionPolicy: 'full', payloadMode: 'minimal' }),
    local: Object.freeze({ settleMultiplier: 1, motionPolicy: 'selective', payloadMode: 'default' }),
    debug: Object.freeze({ settleMultiplier: 1, motionPolicy: 'none', payloadMode: 'verbose' }),
    visualRegression: Object.freeze({ settleMultiplier: 1.5, motionPolicy: 'full', payloadMode: 'default' }),
});

const EVALUATION_CATEGORY_BUILDERS = Object.freeze({
    accessibility: () => ({
        touchTargets: {
            minSizePx: TOUCH_TARGET_POLICY.minSizePx,
            comfortableSizePx: TOUCH_TARGET_POLICY.comfortableSizePx,
        },
        wcag: WCAG_CONTRAST,
    }),
    components: () => ({
        badges: COMPONENT_CONTRACTS.badge,
        cards: COMPONENT_CONTRACTS.card,
        kpiCards: COMPONENT_CONTRACTS.kpiCard,
        modals: COMPONENT_CONTRACTS.modal,
        sliders: COMPONENT_CONTRACTS.slider,
    }),
    layout: () => ({
        spacing: LAYOUT_SPACING_POLICY,
        overflow: OVERFLOW_POLICY,
        stability: LAYOUT_STABILITY_POLICY,
    }),
    motion: () => ({
        resetCss: MOTION_POLICY.resetCss,
        appSpecificRules: MOTION_POLICY.appSpecificRules,
    }),
    runtime: () => ({
        browserCapabilities: BROWSER_CAPABILITIES,
        deviceProfiles: DEVICE_PROFILE_REGISTRY,
        lintProfiles: UI_LINT_PROFILES,
    }),
    screenshots: () => ({
        timings: SCREENSHOT_TIMING_POLICY,
    }),
    themes: () => ({
        themeNames: ['light', 'dark', 'highContrast'],
    }),
    legacy: () => ({
        OVERFLOW_TOLERANCE_PX: OVERFLOW_POLICY.warningPx,
        FOOTER_OVERLAP_TOLERANCE_PX: 1,
        VERTICAL_GAP_MIN: LAYOUT_SPACING_POLICY.verticalGapMinPx,
        VERTICAL_GAP_MAX: LAYOUT_SPACING_POLICY.verticalGapMaxPx,
        STACK_GAP_VARIANCE_TOLERANCE_PX: LAYOUT_SPACING_POLICY.stackGapVarianceTolerancePx,
        SCROLL_EDGE_CLEARANCE_MIN: LAYOUT_SPACING_POLICY.scrollEdgeClearanceMinPx,
        GHOST_SCROLL_DELTA_MAX_PX: LAYOUT_SPACING_POLICY.ghostScrollDeltaMaxPx,
        GHOST_SCROLL_MIN_HEIGHT_PX: LAYOUT_SPACING_POLICY.ghostScrollMinHeightPx,
        COMPONENT_LAYOUT_SHIFT_THRESHOLD_PX: LAYOUT_STABILITY_POLICY.componentLayoutShiftThresholdPx,
        COMPONENT_LAYOUT_SHIFT_SETTLE_MS: SCREENSHOT_TIMING_POLICY.componentLayoutShiftSettleMs,
        CLICK_TARGET_MIN_SIZE_PX: TOUCH_TARGET_POLICY.minSizePx,
        LOGS_DELETE_HAIRLINE_TOLERANCE_PX: 2,
        BADGE_FONT_SIZE_TOLERANCE_PX: COMPONENT_CONTRACTS.badge.fontSizeTolerancePx,
        BADGE_FONT_WEIGHT_TOLERANCE: COMPONENT_CONTRACTS.badge.fontWeightTolerance,
        BADGE_RADIUS_TOLERANCE_PX: 1,
        BADGE_PADDING_TOLERANCE_PX: COMPONENT_CONTRACTS.badge.paddingTolerancePx,
        MONOSPACE_RADIUS_TOLERANCE_PX: 1,
        MONOSPACE_PADDING_TOLERANCE_PX: 1,
        SLIDER_TICK_ALIGNMENT_TOLERANCE_PX: COMPONENT_CONTRACTS.slider.tickAlignmentTolerancePx,
        SLIDER_VISIBLE_LABEL_GAP_MIN_PX: COMPONENT_CONTRACTS.slider.visibleLabelGapMinPx,
        SLIDER_LABEL_HIDDEN_OPACITY_MAX: COMPONENT_CONTRACTS.slider.labelHiddenOpacityMax,
        MODAL_BACKDROP_BLUR_EXPECTED_PX: COMPONENT_CONTRACTS.modal.backdrop.blurPx,
        MODAL_BACKDROP_BLUR_TOLERANCE_PX: COMPONENT_CONTRACTS.modal.backdrop.blurTolerancePx,
        MODAL_BACKDROP_SATURATE_EXPECTED: COMPONENT_CONTRACTS.modal.backdrop.saturate,
        MODAL_BACKDROP_SATURATE_TOLERANCE: COMPONENT_CONTRACTS.modal.backdrop.saturateTolerance,
        MODAL_BACKDROP_ALPHA_EXPECTED: COMPONENT_CONTRACTS.modal.backdrop.alpha,
        MODAL_BACKDROP_ALPHA_TOLERANCE: COMPONENT_CONTRACTS.modal.backdrop.alphaTolerance,
        FORM_SWITCH_MAX_HEIGHT_PX: FORM_CONTRACT.switchMaxHeightPx,
        FORM_SWITCH_HEIGHT_TOLERANCE_PX: FORM_CONTRACT.switchHeightTolerancePx,
        INPUT_GROUP_HEIGHT_TOLERANCE_PX: FORM_CONTRACT.inputGroupHeightTolerancePx,
        ABOUT_TOP_ROW_HEIGHT_TOLERANCE_PX: ABOUT_CONTRACT.topRowHeightTolerancePx,
        ABOUT_MOBILE_STACK_GAP_VARIANCE_TOLERANCE_PX: ABOUT_CONTRACT.mobileStackGapVarianceTolerancePx,
        ABOUT_APPLICATION_DETAILS_REQUIRED_ROWS: ABOUT_CONTRACT.applicationDetailsRequiredRows,
        ABOUT_APPLICATION_DETAILS_FORBIDDEN_ROWS: ABOUT_CONTRACT.applicationDetailsForbiddenRows,
        ABOUT_UPDATE_TABLE_LABELS: ABOUT_CONTRACT.updateTableLabels,
        STATUS_FLOW_NODE_EXPECTATIONS: STATUS_CONTRACT.flowNodes,
        STATUS_FLOW_CONNECTOR_EXPECTATIONS: STATUS_CONTRACT.flowConnectors,
        STATUS_DETAIL_CARD_TITLES: STATUS_CONTRACT.detailCardTitles,
        WCAG_NORMAL_AA: WCAG_CONTRAST.NORMAL_AA,
        WCAG_LARGE_AA: WCAG_CONTRAST.LARGE_AA,
        WCAG_LARGE_TEXT_SIZE_PX: WCAG_CONTRAST.LARGE_TEXT_SIZE_PX,
        WCAG_LARGE_TEXT_SIZE_BOLD_PX: WCAG_CONTRAST.LARGE_TEXT_SIZE_BOLD_PX,
        WCAG_BOLD_WEIGHT: WCAG_CONTRAST.BOLD_WEIGHT,
    }),
});

export function buildEvaluationPayload({ categories = Object.keys(EVALUATION_CATEGORY_BUILDERS) } = {}) {
    const payload = {};

    for (const category of categories) {
        const buildCategory = EVALUATION_CATEGORY_BUILDERS[category];
        if (!buildCategory) continue;
        payload[category] = buildCategory();
    }

    return payload;
}

export function buildSerializableConstants({ categories = Object.keys(EVALUATION_CATEGORY_BUILDERS) } = {}) {
    const payload = {};

    for (const category of categories) {
        const buildCategory = EVALUATION_CATEGORY_BUILDERS[category];
        if (!buildCategory) continue;
        Object.assign(payload, buildCategory());
    }

    return payload;
}

export const DEFAULT_EVALUATION_CATEGORIES = Object.keys(EVALUATION_CATEGORY_BUILDERS);