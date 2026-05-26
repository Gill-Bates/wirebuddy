//
// tools/ui-lint/lib/dom-health.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { classifyUxIssue } from './ux-severity.mjs';

function inferComponent(route = '') {
    const value = String(route).toLowerCase();
    if (value.includes('/peers')) return 'peers';
    if (value.includes('/nodes')) return 'nodes';
    if (value.includes('/dashboard')) return 'dashboard';
    if (value.includes('/users')) return 'users';
    if (value.includes('/dns')) return 'dns';
    if (value.includes('/traffic')) return 'traffic';
    if (value.includes('/status')) return 'status';
    if (value.includes('/settings')) return 'settings';
    if (value.includes('/about')) return 'about';
    return 'ui';
}

function toCount(value) {
    return Array.isArray(value) ? value.length : Number(value || 0);
}

export function buildDomHealthState(metrics = {}) {
    const horizontalOverflow = metrics.horizontalOverflow || {};
    const clippedButtons = metrics.clippedButtons || [];
    const clickTargetsTooSmall = metrics.clickTargetsTooSmall || [];
    const hiddenInteractiveElements = metrics.hiddenInteractiveElements || [];
    const layoutShift = metrics.layoutShift || {};
    const componentLayoutShift = metrics.componentLayoutShift || [];

    return {
        horizontalOverflow: {
            hasOverflow: Boolean(horizontalOverflow.hasOverflow),
            scrollWidth: horizontalOverflow.scrollWidth ?? null,
            viewportWidth: horizontalOverflow.viewportWidth ?? null,
            offenderCount: toCount(horizontalOverflow.offenders),
            offenders: horizontalOverflow.offenders || [],
        },
        clippedButtonCount: clippedButtons.length,
        touchTargetViolationCount: clickTargetsTooSmall.length,
        hiddenInteractiveCount: hiddenInteractiveElements.length,
        layoutShiftValue: Number(layoutShift.value || 0),
        layoutShiftCount: Number(layoutShift.count || 0),
        componentLayoutShiftCount: componentLayoutShift.length,
        componentLayoutShift,
        browserSpecific: {
            safariTableOverflowRiskCount: metrics.safariTableOverflowRisks?.length || 0,
        },
    };
}

export function enrichAuditEntries(entries = [], context = {}) {
    const domHealth = context.domHealth || buildDomHealthState(context.metrics || {});
    const route = context.route || context.url || null;
    const component = context.component || context.scope || inferComponent(route || '');
    const browser = context.browser || null;
    const timestamp = context.timestamp || Date.now();

    return entries.map((entry) => {
        const text = String(entry.text || '');
        const signals = [];

        if (/resizeobserver/i.test(text)) signals.push('resize-observer');
        if (domHealth.horizontalOverflow.hasOverflow) signals.push('horizontal-overflow');
        if (domHealth.layoutShiftCount > 0 || domHealth.componentLayoutShiftCount > 0) signals.push('layout-shift');
        if (domHealth.touchTargetViolationCount > 0) signals.push('touch-target-violation');
        if (domHealth.clippedButtonCount > 0) signals.push('clipped-action');

        const uxSeverity = classifyUxIssue({
            kind: signals[0] || entry.kind,
            text,
            domHealth,
            severity: entry.severity,
        });

        return {
            ...entry,
            route,
            component,
            browser,
            timestamp: entry.timestamp || timestamp,
            uxSeverity,
            correlatedSignals: signals,
            // Note: domHealth intentionally omitted to reduce JSON output size
        };
    });
}

export function correlateConsoleEntries(entries = [], metricsOrDomHealth = {}, context = {}) {
    const domHealth = metricsOrDomHealth.horizontalOverflow || metricsOrDomHealth.layoutShiftCount !== undefined
        ? metricsOrDomHealth
        : buildDomHealthState(metricsOrDomHealth);

    return enrichAuditEntries(entries, { ...context, domHealth });
}