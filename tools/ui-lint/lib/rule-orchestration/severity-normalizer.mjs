//
// tools/ui-lint/lib/rule-orchestration/severity-normalizer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const CANONICAL_SEVERITIES = new Map([
    ['critical', 'critical'],
    ['error', 'error'],
    ['serious', 'error'],
    ['warning', 'warning'],
    ['warn', 'warning'],
    ['notice', 'notice'],
    ['info', 'info'],
    ['informational', 'info'],
]);

export function normalizeSeverity(severity, fallback = 'warning') {
    if (!severity) return fallback;
    const normalized = CANONICAL_SEVERITIES.get(String(severity).toLowerCase());
    return normalized || fallback;
}

export function normalizeSeverityByBrowser(ruleMeta, browser, fallback = 'warning') {
    const browserSeverity = browser ? ruleMeta.severityByBrowser?.[browser] : null;
    return normalizeSeverity(browserSeverity || ruleMeta.severity || fallback, fallback);
}

export function severityWeight(severity) {
    switch (normalizeSeverity(severity)) {
        case 'critical': return 25;
        case 'error': return 12;
        case 'warning': return 4;
        case 'notice': return 2;
        case 'info': return 1;
        default: return 1;
    }
}
