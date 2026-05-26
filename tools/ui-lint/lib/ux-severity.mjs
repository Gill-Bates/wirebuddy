//
// tools/ui-lint/lib/ux-severity.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const CRITICAL_ISSUE_KINDS = new Set([
    'horizontal-overflow',
    'clipped-action',
    'clipped-actions',
    'inaccessible-modal-control',
    'invisible-interactive',
    'touch-target',
    'touch-target-violation',
]);

const SERIOUS_ISSUE_KINDS = new Set([
    'wrapped-action-group',
    'badge-overflow',
    'entity-overlap',
    'layout-shift',
    'flex-overflow',
    'scroll-trap',
    'grid-conflict',
    'responsive-collapse',
    'browser-regression',
]);

const MINOR_ISSUE_KINDS = new Set([
    'wrapped-badge',
    'spacing-inconsistency',
    'low-priority-warning',
]);

const SEVERITY_POINTS = {
    critical: 8,
    serious: 4,
    minor: 1,
};

function normalizeKind(issue) {
    return String(issue.kind || issue.type || issue.category || issue.issue || '')
        .trim()
        .toLowerCase()
        .replace(/_/g, '-');
}

export function classifyUxIssue(issue = {}) {
    if (issue.severity && ['critical', 'serious', 'minor'].includes(issue.severity)) {
        return issue.severity;
    }

    const kind = normalizeKind(issue);
    if (CRITICAL_ISSUE_KINDS.has(kind)) return 'critical';
    if (SERIOUS_ISSUE_KINDS.has(kind)) return 'serious';
    if (MINOR_ISSUE_KINDS.has(kind)) return 'minor';

    const text = String(issue.text || '').toLowerCase();
    const domHealth = issue.domHealth || {};

    if (/resizeobserver/.test(text)) {
        if (domHealth.horizontalOverflow?.hasOverflow) return 'critical';
        if ((domHealth.layoutShiftCount || 0) > 0) return 'serious';
    }

    if (/clipped|cut off|overflow/.test(text)) {
        return 'serious';
    }

    return 'minor';
}

export function scoreUxIssues(issues = []) {
    const critical = [];
    const serious = [];
    const minor = [];
    let score = 0;

    for (const issue of issues) {
        const severity = classifyUxIssue(issue);
        const entry = { ...issue, severity };

        if (severity === 'critical') {
            critical.push(entry);
        } else if (severity === 'serious') {
            serious.push(entry);
        } else {
            minor.push(entry);
        }

        score += SEVERITY_POINTS[severity] || 0;
    }

    return {
        score,
        total: issues.length,
        critical,
        serious,
        minor,
    };
}