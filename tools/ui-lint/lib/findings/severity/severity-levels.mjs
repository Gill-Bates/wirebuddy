//
// tools/ui-lint/lib/findings/severity/severity-levels.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const SEVERITY_LEVELS = Object.freeze({
    critical: 'critical',
    error: 'error',
    warning: 'warning',
    notice: 'notice',
    info: 'info',
});

export const RISK_LEVELS = Object.freeze({
    blocker: 'blocker',
    degraded: 'degraded',
    cosmetic: 'cosmetic',
});
