//
// tools/ui-lint/lib/findings/policies/dashboard-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { countFindingRule, customFindingRule } from '../engine/policy-engine.mjs';
import { isDashboardScope, isMobileDashboardScope } from '../scopes/dashboard.mjs';

export function buildDashboardPolicy() {
    return {
        id: 'dashboard-policy',
        owner: 'dashboard-team',
        rules: [
            customFindingRule({
                id: 'dashboard-top-row',
                type: 'dashboard-top-row',
                category: 'layout',
                scopes: ['dashboard'],
                build(context) {
                    const alignment = context.metrics.spacing?.dashboardTopRowAlignment;
                    if (!alignment || alignment.aligned) return [];
                    return [{
                        id: 'dashboard-top-row-variance',
                        type: 'dashboard-top-row',
                        category: 'layout',
                        severity: 'warning',
                        count: 1,
                        value: alignment.variance,
                        message: 'Dashboard top row alignment issue',
                        explanation: 'The dashboard top row does not align to the contract.',
                        remediation: 'Match the card heights and container alignment.',
                        legacyKey: `dashboardTopRowVariance=${alignment.variance}`,
                    }];
                },
            }),
            customFindingRule({
                id: 'dashboard-mobile-stack-order',
                type: 'dashboard-mobile-stack-order',
                category: 'layout',
                scopes: ['dashboard'],
                build(context) {
                    const order = context.metrics.spacing?.dashboardMobileStackOrder;
                    if (!order || (order.speedtestAboveMap && order.mapAboveRecent)) return [];
                    return [{
                        id: 'dashboard-mobile-stack-order',
                        type: 'dashboard-mobile-stack-order',
                        category: 'layout',
                        severity: 'warning',
                        count: 1,
                        message: 'Dashboard mobile stack order issue',
                        explanation: 'The mobile dashboard stack order is inconsistent with the expected sequence.',
                        remediation: 'Reorder the stack so the critical cards appear first.',
                        legacyKey: 'dashboardMobileStackOrder',
                    }];
                },
            }),
            customFindingRule({
                id: 'kpi-padding-mismatch',
                type: 'kpi-padding-mismatch',
                category: 'visual',
                scopes: ['dashboard'],
                build(context) {
                    const cards = context.metrics.spacing?.kpiCards || [];
                    const expected = context.metrics.spacing?.kpiPaddingExpectedPx ?? 0;
                    const tolerance = context.metrics.spacing?.kpiPaddingTolerancePx ?? 0;
                    const mismatches = cards.filter((card) =>
                        Math.abs((card.paddingTop ?? expected) - expected) > tolerance ||
                        Math.abs((card.paddingBottom ?? expected) - expected) > tolerance
                    );
                    if (!mismatches.length) return [];
                    return [{
                        id: 'kpi-padding-mismatch',
                        type: 'kpi-padding-mismatch',
                        category: 'visual',
                        severity: 'warning',
                        count: mismatches.length,
                        value: mismatches,
                        message: 'KPI padding mismatch detected',
                        explanation: 'KPI card padding deviates from the expected contract.',
                        remediation: 'Normalize KPI padding to the design token.',
                        legacyKey: `kpiPaddingMismatch=${mismatches.length}`,
                    }];
                },
            }),
            customFindingRule({
                id: 'kpi-icon-size-mismatch',
                type: 'kpi-icon-size-mismatch',
                category: 'visual',
                scopes: ['dashboard'],
                build(context) {
                    const cards = context.metrics.spacing?.kpiCards || [];
                    const min = context.metrics.spacing?.kpiIconMinPx ?? 0;
                    const max = context.metrics.spacing?.kpiIconMaxPx ?? Number.POSITIVE_INFINITY;
                    const mismatches = cards.filter((card) => card.iconSize != null && (card.iconSize < min || card.iconSize > max));
                    if (!mismatches.length) return [];
                    return [{
                        id: 'kpi-icon-size-mismatch',
                        type: 'kpi-icon-size-mismatch',
                        category: 'visual',
                        severity: 'warning',
                        count: mismatches.length,
                        value: mismatches,
                        message: 'KPI icon size mismatch detected',
                        explanation: 'KPI icon sizing deviates from the allowed contract.',
                        remediation: 'Use the expected icon size token.',
                        legacyKey: `kpiIconSizeMismatch=${mismatches.length}`,
                    }];
                },
            }),
            countFindingRule({
                id: 'cards-missing-kpi-class',
                type: 'cards-missing-kpi-class',
                category: 'layout',
                scopes: ['dashboard'],
                metricPath: 'metrics.spacing.cardsMissingKpiClass',
                legacyKey: (context, count) => `cardsMissingKpiClass=${count}`,
                message: 'Cards missing KPI class detected',
                explanation: 'A dashboard KPI card does not carry the required class contract.',
                remediation: 'Apply the KPI class to preserve the expected layout behavior.',
            }),
            customFindingRule({
                id: 'dashboard-kpi-width-variance',
                type: 'dashboard-kpi-width-variance',
                category: 'layout',
                scopes: ['dashboard'],
                build(context) {
                    const widths = context.metrics.spacing?.statCardWidths || [];
                    if (widths.length <= 1) return [];
                    const variance = Math.max(...widths) - Math.min(...widths);
                    if (variance <= 8) return [];
                    return [{
                        id: 'dashboard-kpi-width-variance',
                        type: 'dashboard-kpi-width-variance',
                        category: 'layout',
                        severity: 'warning',
                        count: 1,
                        value: variance,
                        message: 'Dashboard KPI width variance detected',
                        explanation: 'Dashboard KPI cards are not the same width.',
                        remediation: 'Normalize the KPI widths or constrain the flex basis.',
                        legacyKey: `kpiCardWidthVariance=${variance}`,
                    }];
                },
            }),
            customFindingRule({
                id: 'recent-peer-divider-contract',
                type: 'recent-peer-divider-contract',
                category: 'visual',
                scopes: ['dashboard'],
                build(context) {
                    const rows = context.metrics.spacing?.recentPeerRows || [];
                    const offenders = rows.filter((row) => row.hasLegacyBorderBottom || (!row.isLast && !row.hasPseudoDivider));
                    if (!offenders.length) return [];
                    return [{
                        id: 'recent-peer-divider-contract',
                        type: 'recent-peer-divider-contract',
                        category: 'visual',
                        severity: 'warning',
                        count: offenders.length,
                        value: offenders,
                        message: 'Recent peer dividers do not span the row correctly',
                        explanation: 'Recent peer rows still rely on border-bottom or are missing a full-width divider pseudo-element, which causes visibly truncated hairlines.',
                        remediation: 'Render the divider with a row-level ::after pseudo-element and remove border-bottom from the row class list.',
                        legacyKey: `recentPeerDividerIssues=${offenders.length}`,
                    }];
                },
            }),
            customFindingRule({
                id: 'chart-empty-state-off-center',
                type: 'chart-empty-state-off-center',
                category: 'layout',
                scopes: ['dashboard'],
                build(context) {
                    const states = context.metrics.spacing?.chartEmptyStateCentering || [];
                    const offenders = states.filter((state) => state.centered === false);
                    if (!offenders.length) return [];
                    return [{
                        id: 'chart-empty-state-off-center',
                        type: 'chart-empty-state-off-center',
                        category: 'layout',
                        severity: isMobileDashboardScope(context) ? 'error' : 'warning',
                        count: offenders.length,
                        value: offenders,
                        message: 'Chart empty state is not horizontally centered',
                        explanation: 'A visible chart empty state is horizontally offset within its container, which makes the card look visually broken.',
                        remediation: 'Stretch the empty-state container to the parent width and center its content within the card.',
                        legacyKey: `chartEmptyStateOffCenter=${offenders.length}`,
                    }];
                },
            }),
        ],
    };
}
