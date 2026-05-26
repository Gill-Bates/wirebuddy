//
// tools/ui-lint/lib/accessibility/axe-runner.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { normalizeAccessibilityFinding } from './violation-normalizer.mjs';

export async function runAxeAudit(page) {
    try {
        const { default: AxeBuilder } = await import('@axe-core/playwright');
        const axeResults = await new AxeBuilder({ page })
            .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'])
            .analyze();

        const violations = axeResults.violations || [];
        const critical = violations.filter((violation) => violation.impact === 'critical');
        const serious = violations.filter((violation) => violation.impact === 'serious');
        const moderate = violations.filter((violation) => violation.impact === 'moderate');
        const minor = violations.filter((violation) => violation.impact === 'minor');

        return {
            passed: axeResults.passes?.length || 0,
            violations: violations.length,
            critical: critical.map((violation) => normalizeAccessibilityFinding('axe', violation)),
            serious: serious.map((violation) => normalizeAccessibilityFinding('axe', violation)),
            moderate: moderate.map((violation) => normalizeAccessibilityFinding('axe', violation)),
            minor: minor.map((violation) => normalizeAccessibilityFinding('axe', violation)),
            findings: violations.map((violation) => normalizeAccessibilityFinding('axe', violation)),
            incomplete: axeResults.incomplete?.length || 0,
        };
    } catch (err) {
        return {
            error: err.message,
            passed: 0,
            violations: 0,
            critical: [],
            serious: [],
            moderate: [],
            minor: [],
            findings: [],
            incomplete: 0,
        };
    }
}
