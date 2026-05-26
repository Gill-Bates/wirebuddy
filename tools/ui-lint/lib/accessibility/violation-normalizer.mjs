//
// tools/ui-lint/lib/accessibility/violation-normalizer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { mapAxeImpactToSeverity } from './wcag-mapping.mjs';

export function normalizeAccessibilityFinding(provider, violation) {
    return {
        provider,
        id: violation.id || violation.ruleId || violation.code || 'unknown',
        severity: mapAxeImpactToSeverity(violation.impact || violation.severity),
        category: violation.tags?.[0] || violation.category || 'a11y',
        message: violation.description || violation.help || violation.message || 'Accessibility violation',
        help: violation.help || null,
        helpUrl: violation.helpUrl || null,
        nodes: (violation.nodes || []).slice(0, 10).map((node) => ({
            target: node.target || [],
            html: node.html?.slice?.(0, 250) || null,
            failureSummary: node.failureSummary || null,
        })),
    };
}
