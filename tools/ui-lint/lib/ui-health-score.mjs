//
// tools/ui-lint/lib/ui-health-score.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildDomHealthState } from './dom-health.mjs';
import { scoreUxIssues } from './ux-severity.mjs';

function count(value) {
    return Array.isArray(value) ? value.length : Number(value || 0);
}

function deriveUxIssues(result, domHealth) {
    const metrics = result.metrics || {};
    const issues = [];

    if (domHealth.horizontalOverflow.hasOverflow) {
        issues.push({ kind: 'horizontal-overflow', severity: 'critical', text: 'horizontal page overflow' });
    }

    if (metrics.clippedButtons?.length) {
        issues.push({ kind: 'clipped-actions', severity: 'serious', text: 'clipped action buttons' });
    }

    if (metrics.clickTargetsTooSmall?.length) {
        issues.push({ kind: 'touch-target', severity: 'critical', text: 'touch targets too small' });
    }

    if (metrics.hiddenInteractiveElements?.length) {
        issues.push({ kind: 'invisible-interactive', severity: 'critical', text: 'hidden interactive elements' });
    }

    if (metrics.bootstrapGridIssues?.length || metrics.bootstrapColumnsOutsideRows?.length || metrics.breakpointDisplayConflicts?.length) {
        issues.push({ kind: 'responsive-collapse', severity: 'serious', text: 'responsive layout contract mismatch' });
    }

    if (metrics.navbarCollapseIssues?.length) {
        issues.push({ kind: 'responsive-collapse', severity: 'serious', text: 'navbar collapse mismatch' });
    }

    if (metrics.focusOrderIssues?.length || metrics.focusIndicatorMissing?.length) {
        issues.push({ kind: 'accessibility-regression', severity: 'serious', text: 'focus contract mismatch' });
    }

    if (metrics.scrollEdgeCrowding?.length || metrics.scrollBottomCrowding?.length || metrics.nestedScrollContainers?.length || metrics.flexScrollTraps?.length || metrics.doubleScrollRisk) {
        issues.push({ kind: 'scroll-trap', severity: 'serious', text: 'scroll behavior risk' });
    }

    if (metrics.tableCellOverlapIssues?.length || metrics.visualContainmentIssues?.length) {
        issues.push({ kind: 'entity-overlap', severity: 'serious', text: 'entity layout overlap' });
    }

    if ((metrics.layoutShift?.value || 0) > 0 || metrics.componentLayoutShift?.length) {
        issues.push({ kind: 'layout-shift', severity: 'serious', text: 'layout instability after render' });
    }

    if (metrics.badgeStyleMismatches?.length || metrics.monospaceToneMismatches?.length) {
        issues.push({ kind: 'spacing-inconsistency', severity: 'minor', text: 'visual tone mismatch' });
    }

    if (metrics.safariTableOverflowRisks?.length && (result.browser || '').toLowerCase() === 'webkit') {
        issues.push({ kind: 'browser-regression', severity: 'critical', text: 'webkit overflow risk' });
    }

    const consoleEntries = result.network?.consoleEntries || [];
    const resizeObserverEntries = consoleEntries.filter((entry) => /resizeobserver/i.test(String(entry.text || '')));
    if (resizeObserverEntries.length) {
        issues.push({
            kind: domHealth.horizontalOverflow.hasOverflow ? 'horizontal-overflow' : 'layout-shift',
            severity: domHealth.horizontalOverflow.hasOverflow ? 'critical' : 'serious',
            text: 'ResizeObserver console activity correlated with DOM state',
        });
    }

    return issues;
}

export function buildUIHealthReport(result = {}) {
    const metrics = result.metrics || {};
    const domHealth = buildDomHealthState(metrics);
    const consoleSeverity = result.network?.consoleSeverity || { score: 0, critical: [], serious: [], minor: [], total: 0 };
    const uxIssues = deriveUxIssues(result, domHealth);
    const uxSeverity = scoreUxIssues(uxIssues);

    const accessibilityPenalty =
        count(metrics.axe?.critical) * 12 +
        count(metrics.axe?.serious) * 8 +
        count(metrics.axe?.moderate) * 4 +
        count(metrics.axe?.minor) * 2;

    const screenshotPenalty = Math.round((result.diff?.ratio || 0) * 100);
    const consolePenalty = Math.min(20, consoleSeverity.score * 2);
    const overflowPenalty = domHealth.horizontalOverflow.hasOverflow ? Math.min(30, 15 + domHealth.horizontalOverflow.offenderCount * 2) : 0;
    const interactionPenalty = domHealth.touchTargetViolationCount * 5 + domHealth.hiddenInteractiveCount * 6 + domHealth.clippedButtonCount * 3;
    const layoutPenalty =
        Math.min(20, Math.round(domHealth.layoutShiftValue * 100)) +
        Math.min(12, domHealth.componentLayoutShiftCount * 4);
    const regressionPenalty = result.browser && uxSeverity.critical.some((issue) => issue.kind === 'browser-regression') ? 10 : 0;

    const totalPenalty =
        consolePenalty +
        uxSeverity.score +
        accessibilityPenalty +
        screenshotPenalty +
        overflowPenalty +
        interactionPenalty +
        layoutPenalty +
        regressionPenalty;

    const score = Math.max(0, 100 - totalPenalty);
    const severity = score >= 85 ? 'healthy' : score >= 70 ? 'degraded' : 'critical';

    return {
        route: result.url || null,
        browser: result.browser || null,
        component: result.component || result.scope || result.name || null,
        score,
        severity,
        console: {
            score: consoleSeverity.score,
            critical: consoleSeverity.critical?.length || 0,
            serious: consoleSeverity.serious?.length || 0,
            minor: consoleSeverity.minor?.length || 0,
            total: consoleSeverity.total || 0,
        },
        ux: {
            score: uxSeverity.score,
            critical: uxSeverity.critical.length,
            serious: uxSeverity.serious.length,
            minor: uxSeverity.minor.length,
            issues: uxIssues,
        },
        dom: domHealth,
        accessibility: {
            critical: count(metrics.axe?.critical),
            serious: count(metrics.axe?.serious),
            moderate: count(metrics.axe?.moderate),
            minor: count(metrics.axe?.minor),
            penalty: accessibilityPenalty,
        },
        penalties: {
            console: consolePenalty,
            ux: uxSeverity.score,
            accessibility: accessibilityPenalty,
            screenshot: screenshotPenalty,
            overflow: overflowPenalty,
            interaction: interactionPenalty,
            layout: layoutPenalty,
            browser: regressionPenalty,
        },
        gates: {
            hardBlock: domHealth.horizontalOverflow.hasOverflow || count(metrics.clickTargetsTooSmall) > 0 || uxSeverity.critical.length > 0,
        },
    };
}