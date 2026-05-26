//
// tools/ui-lint/lib/findings/severity/escalation.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { SEVERITY_LEVELS } from './severity-levels.mjs';

export function applyEscalationRules(severity, finding, context) {
    if (finding.type === 'horizontal-overflow' && context.scope === 'auth') {
        return SEVERITY_LEVELS.critical;
    }

    if (finding.type === 'double-scroll-risk' && context.device === 'mobile') {
        return SEVERITY_LEVELS.error;
    }

    return severity;
}
