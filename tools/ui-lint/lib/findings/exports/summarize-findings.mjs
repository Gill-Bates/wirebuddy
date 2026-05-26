//
// tools/ui-lint/lib/findings/exports/summarize-findings.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { evaluateFindings } from '../engine/findings-engine.mjs';
import { buildHumanSummary } from '../explainability/human-summary.mjs';
import { buildMachineSummary } from '../explainability/machine-summary.mjs';
import { buildRemediationHint } from '../explainability/remediation-hints.mjs';
import { isExpectedStatusUnavailable } from '../scopes/status.mjs';
import { SEVERITY_LEVELS } from '../severity/severity-levels.mjs';

function toLegacyStrings(findings, severityFilter) {
    return findings
        .filter((finding) => severityFilter(finding.severity))
        .map((finding) => finding.legacyKey || finding.id);
}

export function summarizeFindings(result) {
    const decision = evaluateFindings(result);
    const findings = decision.findings.map((finding) => ({
        ...buildMachineSummary(finding),
        message: buildHumanSummary(finding),
        explanation: finding.explanation,
        remediation: buildRemediationHint(finding),
    }));

    return {
        findings: toLegacyStrings(decision.findings, (severity) => severity === SEVERITY_LEVELS.error || severity === SEVERITY_LEVELS.critical || severity === 'error' || severity === 'critical' || severity === 'warning' || severity === 'notice' || severity === 'info'),
        hardFindings: toLegacyStrings(decision.findings, (severity) => severity === SEVERITY_LEVELS.error || severity === SEVERITY_LEVELS.critical),
        warnings: toLegacyStrings(decision.findings, (severity) => severity !== SEVERITY_LEVELS.error && severity !== SEVERITY_LEVELS.critical),
        decision,
        structuredFindings: findings,
        summary: decision.summary,
    };
}

export { isExpectedStatusUnavailable };
