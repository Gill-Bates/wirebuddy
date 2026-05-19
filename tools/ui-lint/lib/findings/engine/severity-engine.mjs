//
// tools/ui-lint/lib/findings/engine/severity-engine.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { SEVERITY_LEVELS, RISK_LEVELS } from '../severity/severity-levels.mjs';
import { SEVERITY_WEIGHTS } from '../severity/severity-weights.mjs';
import { applyDowngradeRules } from '../severity/downgrade-rules.mjs';
import { applyEscalationRules } from '../severity/escalation.mjs';

export function evaluateSeverity(finding, context) {
    const baseSeverity = finding.severity || SEVERITY_LEVELS.warning;
    const downgraded = applyDowngradeRules(baseSeverity, finding, context);
    return applyEscalationRules(downgraded, finding, context);
}

export function severityToRiskLevel(severity) {
    if (severity === SEVERITY_LEVELS.critical || severity === SEVERITY_LEVELS.error) {
        return RISK_LEVELS.blocker;
    }
    if (severity === SEVERITY_LEVELS.warning) {
        return RISK_LEVELS.degraded;
    }
    return RISK_LEVELS.cosmetic;
}

export function severityWeight(severity, category = 'default') {
    return (SEVERITY_WEIGHTS[category] || SEVERITY_WEIGHTS.default)[severity] || 1;
}
