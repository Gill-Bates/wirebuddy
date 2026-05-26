//
// tools/ui-lint/lib/findings/severity/downgrade-rules.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { SEVERITY_LEVELS } from './severity-levels.mjs';

export function applyDowngradeRules(severity, finding, context) {
    if (context.statusUnavailableExpected && finding.type === 'modal-backdrop') {
        return SEVERITY_LEVELS.notice;
    }

    return severity;
}
