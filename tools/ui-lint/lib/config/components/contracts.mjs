//
// tools/ui-lint/lib/config/components/contracts.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { resolveOptionalToken } from '../tokens/resolver.mjs';

export const BADGE_CONTRACT = Object.freeze({
    radiusPx: resolveOptionalToken('badge.radius', 6, { category: 'components' }),
    fontSizeTolerancePx: 0.5,
    fontWeightTolerance: 50,
    paddingTolerancePx: 1,
});

export const CARD_CONTRACT = Object.freeze({
    borderRadiusPx: resolveOptionalToken('card.radius', 12, { category: 'components' }),
    borderRadiusTolerancePx: 1,
    compactAction: Object.freeze({
        marginTopMaxPx: 10,
        paddingTopMaxPx: 2,
        borderTopMaxPx: 0.5,
    }),
});

export const KPI_CARD_CONTRACT = Object.freeze({
    desktop: Object.freeze({
        padding: Object.freeze({ expectedPx: 16, tolerancePx: 1 }),
        icon: Object.freeze({ minPx: 32, maxPx: 40 }),
    }),
    compactDashboard: Object.freeze({
        padding: Object.freeze({ expectedPx: 10, tolerancePx: 2 }),
        icon: Object.freeze({ minPx: 18, maxPx: 26 }),
    }),
    mobile: Object.freeze({
        padding: Object.freeze({ expectedPx: 16, tolerancePx: 1 }),
        icon: Object.freeze({ minPx: 24, maxPx: 32 }),
    }),
});

export const MODAL_CONTRACT = Object.freeze({
    backdrop: Object.freeze({
        blurPx: 8,
        blurTolerancePx: 0.25,
        saturate: 0.8,
        saturateTolerance: 0.05,
        alpha: 0.6,
        alphaTolerance: 0.05,
    }),
});

export const SLIDER_CONTRACT = Object.freeze({
    tickAlignmentTolerancePx: 3,
    visibleLabelGapMinPx: 4,
    labelHiddenOpacityMax: 0.05,
});

export const FORM_CONTRACT = Object.freeze({
    switchMaxHeightPx: 22,
    switchHeightTolerancePx: 1,
    inputGroupHeightTolerancePx: 2,
});

export const ABOUT_CONTRACT = Object.freeze({
    topRowHeightTolerancePx: 2,
    mobileStackGapVarianceTolerancePx: 2,
    applicationDetailsRequiredRows: ['Python', 'Timezone', 'WireGuard', 'Unbound'],
    applicationDetailsForbiddenRows: ['Build'],
    updateTableLabels: ['Current', 'Latest', 'Released'],
});

export const STATUS_CONTRACT = Object.freeze({
    flowNodes: [
        { key: 'client', label: 'Client', icon: 'devices' },
        { key: 'wireguard', label: 'WireGuard', icon: 'vpn_lock' },
        { key: 'internet', label: 'Internet', icon: 'public' },
    ],
    flowConnectors: ['client-wireguard', 'wireguard-internet'],
    detailCardTitles: ['Public Client IP', 'Outbound IP'],
});

const COMPONENT_CONTRACT_REGISTRY = {
    badge: BADGE_CONTRACT,
    card: CARD_CONTRACT,
    kpiCard: KPI_CARD_CONTRACT,
    modal: MODAL_CONTRACT,
    slider: SLIDER_CONTRACT,
};

export const COMPONENT_CONTRACTS = COMPONENT_CONTRACT_REGISTRY;

export function registerComponentContract(name, contract) {
    COMPONENT_CONTRACT_REGISTRY[name] = contract;
    return COMPONENT_CONTRACTS[name];
}

export function getComponentContract(name) {
    return COMPONENT_CONTRACT_REGISTRY[name] || null;
}

export function getComponentContracts() {
    return { ...COMPONENT_CONTRACT_REGISTRY };
}

export const KPI_CARD_PADDING_EXPECTED = KPI_CARD_CONTRACT.desktop.padding.expectedPx;
export const KPI_CARD_PADDING_TOLERANCE = KPI_CARD_CONTRACT.desktop.padding.tolerancePx;
export const KPI_ICON_MIN = KPI_CARD_CONTRACT.desktop.icon.minPx;
export const KPI_ICON_MAX = KPI_CARD_CONTRACT.desktop.icon.maxPx;
export const DASHBOARD_COMPACT_KPI_CARD_PADDING_EXPECTED = KPI_CARD_CONTRACT.compactDashboard.padding.expectedPx;
export const DASHBOARD_COMPACT_KPI_CARD_PADDING_TOLERANCE = KPI_CARD_CONTRACT.compactDashboard.padding.tolerancePx;
export const DASHBOARD_COMPACT_KPI_ICON_MIN = KPI_CARD_CONTRACT.compactDashboard.icon.minPx;
export const DASHBOARD_COMPACT_KPI_ICON_MAX = KPI_CARD_CONTRACT.compactDashboard.icon.maxPx;
export const KPI_VISUAL_DRIFT_THRESHOLD = 0.01;
export const KPI_HEIGHT_TOLERANCE_PX = 2;
export const KPI_ROW_VARIANCE_MAX = 3;
export const KPI_ICON_CENTER_TOLERANCE_PX = 4;
export const KPI_ICON_NEUTRAL_COLOR_DISTANCE_MAX = 12;
export const KPI_CONTEXTUAL_ICON_CLASSES = ['text-primary', 'text-success', 'text-info', 'text-danger', 'text-warning'];
export const SETTINGS_TAB_COLOR_DISTANCE_MAX = 12;
export const DASHBOARD_TRANSFER_COLOR_DISTANCE_MIN = 40;
export const KPI_CARD_REQUIRED_SCOPES = ['dashboard', 'dns'];
export const ABOUT_TOP_ROW_HEIGHT_TOLERANCE_PX = ABOUT_CONTRACT.topRowHeightTolerancePx;
export const ABOUT_MOBILE_STACK_GAP_VARIANCE_TOLERANCE_PX = ABOUT_CONTRACT.mobileStackGapVarianceTolerancePx;
export const ABOUT_APPLICATION_DETAILS_REQUIRED_ROWS = ABOUT_CONTRACT.applicationDetailsRequiredRows;
export const ABOUT_APPLICATION_DETAILS_FORBIDDEN_ROWS = ABOUT_CONTRACT.applicationDetailsForbiddenRows;
export const ABOUT_UPDATE_TABLE_LABELS = ABOUT_CONTRACT.updateTableLabels;
export const STATUS_FLOW_NODE_EXPECTATIONS = STATUS_CONTRACT.flowNodes;
export const STATUS_FLOW_CONNECTOR_EXPECTATIONS = STATUS_CONTRACT.flowConnectors;
export const STATUS_DETAIL_CARD_TITLES = STATUS_CONTRACT.detailCardTitles;

export const BADGE_RADIUS_EXPECTED_PX = BADGE_CONTRACT.radiusPx;
export const BADGE_RADIUS_TOLERANCE_PX = 1;
export const BADGE_FONT_SIZE_TOLERANCE_PX = BADGE_CONTRACT.fontSizeTolerancePx;
export const BADGE_FONT_WEIGHT_TOLERANCE = BADGE_CONTRACT.fontWeightTolerance;
export const BADGE_PADDING_TOLERANCE_PX = BADGE_CONTRACT.paddingTolerancePx;
export const CARD_BORDER_RADIUS_EXPECTED_PX = CARD_CONTRACT.borderRadiusPx;
export const CARD_BORDER_RADIUS_TOLERANCE_PX = CARD_CONTRACT.borderRadiusTolerancePx;
export const COMPACT_CARD_ACTION_MARGIN_TOP_MAX_PX = CARD_CONTRACT.compactAction.marginTopMaxPx;
export const COMPACT_CARD_ACTION_PADDING_TOP_MAX_PX = CARD_CONTRACT.compactAction.paddingTopMaxPx;
export const COMPACT_CARD_ACTION_BORDER_TOP_MAX_PX = CARD_CONTRACT.compactAction.borderTopMaxPx;
export const LOGS_DELETE_HAIRLINE_TOLERANCE_PX = 2;
export const MONOSPACE_RADIUS_TOLERANCE_PX = 1;
export const MONOSPACE_PADDING_TOLERANCE_PX = 1;
export const MODAL_BACKDROP_BLUR_EXPECTED_PX = MODAL_CONTRACT.backdrop.blurPx;
export const MODAL_BACKDROP_BLUR_TOLERANCE_PX = MODAL_CONTRACT.backdrop.blurTolerancePx;
export const MODAL_BACKDROP_SATURATE_EXPECTED = MODAL_CONTRACT.backdrop.saturate;
export const MODAL_BACKDROP_SATURATE_TOLERANCE = MODAL_CONTRACT.backdrop.saturateTolerance;
export const MODAL_BACKDROP_ALPHA_EXPECTED = MODAL_CONTRACT.backdrop.alpha;
export const MODAL_BACKDROP_ALPHA_TOLERANCE = MODAL_CONTRACT.backdrop.alphaTolerance;
export const FORM_SWITCH_MAX_HEIGHT_PX = FORM_CONTRACT.switchMaxHeightPx;
export const FORM_SWITCH_HEIGHT_TOLERANCE_PX = FORM_CONTRACT.switchHeightTolerancePx;
export const INPUT_GROUP_HEIGHT_TOLERANCE_PX = FORM_CONTRACT.inputGroupHeightTolerancePx;
export const SLIDER_TICK_ALIGNMENT_TOLERANCE_PX = SLIDER_CONTRACT.tickAlignmentTolerancePx;
export const SLIDER_VISIBLE_LABEL_GAP_MIN_PX = SLIDER_CONTRACT.visibleLabelGapMinPx;
export const SLIDER_LABEL_HIDDEN_OPACITY_MAX = SLIDER_CONTRACT.labelHiddenOpacityMax;