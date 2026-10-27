//
// tools/ui-lint/lib/findings/policies/dashboard-policy.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { countFindingRule, customFindingRule } from '../engine/policy-engine.mjs';
import { isMobileDashboardScope } from '../scopes/dashboard.mjs';

export function buildDashboardPolicy() {
    return {
        id: 'dashboard-policy',
        owner: 'dashboard-team',
        rules: [
            countFindingRule({
                id: 'dashboard-widget-overlap',
                type: 'dashboard-widget-overlap',
                category: 'layout',
                scopes: ['dashboard'],
                severity: 'error',
                metricPath: 'metrics.spacing.dashboardWidgetOverlaps',
                legacyKey: (context, count) => `dashboardWidgetOverlaps=${count}`,
                message: 'Dashboard widgets overlap',
                explanation: 'Visible dashboard widgets occupy the same area.',
                remediation: 'Resolve the overlap in the saved layout or GridStack placement.',
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
