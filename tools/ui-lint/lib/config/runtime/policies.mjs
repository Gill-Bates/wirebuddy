//
// tools/ui-lint/lib/config/runtime/policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { COMPONENT_CONTRACTS, ABOUT_CONTRACT, FORM_CONTRACT, STATUS_CONTRACT } from '../components/contracts.mjs';
import { TOUCH_TARGET_POLICY } from '../accessibility/touch-targets.mjs';
import { FOOTER_POLICY, LAYOUT_POLICY, LAYOUT_SPACING_POLICY, LAYOUT_STABILITY_POLICY, OVERFLOW_POLICY } from '../layout/policies.mjs';
import { MOTION_POLICY } from '../motion/policies.mjs';
import { SCREENSHOT_TIMING_POLICY } from '../screenshots/policies.mjs';
import { WCAG_CONTRAST } from '../accessibility/wcag.mjs';

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

function assertKnownCategories(categories, registry) {
    const unknown = categories.filter((category) => !(category in registry));
    if (unknown.length > 0) {
        throw new TypeError(`Unknown evaluation categories: ${unknown.join(', ')}`);
    }
}

function createLegacyAdapter() {
    return deepFreeze({
        OVERFLOW_TOLERANCE_PX: OVERFLOW_POLICY.warningPx,
        FOOTER_OVERLAP_TOLERANCE_PX: FOOTER_POLICY.overlapTolerancePx,
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
        MONOSPACE_VERTICAL_INSET_TOLERANCE_PX: 2,
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
        FOOTER_Z_INDEX: FOOTER_POLICY.zIndex,
    });
}

export const BROWSER_CAPABILITIES = deepFreeze({
    chromium: Object.freeze({ supportsCLS: true, supportsINP: true, supportsLCP: true, supportsMemory: true }),
    webkit: Object.freeze({ supportsCLS: true, supportsINP: false, supportsLCP: true, supportsMemory: false }),
    firefox: Object.freeze({ supportsCLS: false, supportsINP: true, supportsLCP: true, supportsMemory: true }),
});

export const MOTION_MODES = deepFreeze({
    FULL: 'full',
    SELECTIVE: 'selective',
    NONE: 'none',
});

export const PAYLOAD_MODES = deepFreeze({
    MINIMAL: 'minimal',
    DEFAULT: 'default',
    VERBOSE: 'verbose',
});

export const DEVICE_PROFILE_REGISTRY = deepFreeze({
    desktop: Object.freeze({ class: 'desktop', density: 'comfortable', viewportScale: 1 }),
    tablet: Object.freeze({ class: 'tablet', density: 'balanced', viewportScale: 0.85 }),
    mobile: Object.freeze({ class: 'mobile', density: 'compact', viewportScale: 0.72 }),
});

export const UI_LINT_PROFILES = deepFreeze({
    ci: { settleMultiplier: 1.25, motionPolicy: MOTION_MODES.FULL, payloadMode: PAYLOAD_MODES.MINIMAL },
    local: { settleMultiplier: 1, motionPolicy: MOTION_MODES.SELECTIVE, payloadMode: PAYLOAD_MODES.DEFAULT },
    debug: { settleMultiplier: 1, motionPolicy: MOTION_MODES.NONE, payloadMode: PAYLOAD_MODES.VERBOSE },
    visualRegression: { settleMultiplier: 1.5, motionPolicy: MOTION_MODES.FULL, payloadMode: PAYLOAD_MODES.DEFAULT },
});

const EVALUATION_CATEGORIES = deepFreeze({
    accessibility: {
        touchTargets: {
            minSizePx: TOUCH_TARGET_POLICY.minSizePx,
            comfortableSizePx: TOUCH_TARGET_POLICY.comfortableSizePx,
        },
        wcag: WCAG_CONTRAST,
    },
    components: {
        badges: COMPONENT_CONTRACTS.badge,
        cards: COMPONENT_CONTRACTS.card,
        kpiCards: COMPONENT_CONTRACTS.kpiCard,
        modals: COMPONENT_CONTRACTS.modal,
        sliders: COMPONENT_CONTRACTS.slider,
    },
    layout: {
        spacing: LAYOUT_SPACING_POLICY,
        overflow: OVERFLOW_POLICY,
        stability: LAYOUT_STABILITY_POLICY,
        footer: FOOTER_POLICY,
        policy: LAYOUT_POLICY,
    },
    motion: {
        resetCss: MOTION_POLICY.resetCss,
        appSpecificRules: MOTION_POLICY.appSpecificRules,
    },
    runtime: {
        browserCapabilities: BROWSER_CAPABILITIES,
        deviceProfiles: DEVICE_PROFILE_REGISTRY,
        lintProfiles: UI_LINT_PROFILES,
        motionModes: MOTION_MODES,
        payloadModes: PAYLOAD_MODES,
    },
    screenshots: {
        timings: SCREENSHOT_TIMING_POLICY,
    },
    themes: {
        themeNames: ['light', 'dark', 'highContrast'],
    },
    legacy: createLegacyAdapter(),
});

const CATEGORY_NAMES = deepFreeze(Object.keys(EVALUATION_CATEGORIES));

export function buildEvaluationPayload({ categories = CATEGORY_NAMES } = {}) {
    assertKnownCategories(categories, EVALUATION_CATEGORIES);
    const payload = {};

    for (const category of categories) {
        payload[category] = EVALUATION_CATEGORIES[category];
    }

    return payload;
}

export function buildSerializableConstants({ categories = CATEGORY_NAMES } = {}) {
    assertKnownCategories(categories, EVALUATION_CATEGORIES);
    const payload = {};

    for (const category of categories) {
        const categoryPayload = EVALUATION_CATEGORIES[category];
        for (const [key, value] of Object.entries(categoryPayload)) {
            if (key in payload) {
                throw new TypeError(`Duplicate serializable constant: ${key} (category: ${category})`);
            }
            payload[key] = value;
        }
    }

    return payload;
}

export const DEFAULT_EVALUATION_CATEGORIES = CATEGORY_NAMES;