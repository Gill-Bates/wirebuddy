//
// tools/ui-lint/lib/findings/scopes/dashboard.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function isDashboardScope(context) {
    return context.scope === 'dashboard';
}

export function isMobileDashboardScope(context) {
    return isDashboardScope(context) && context.device === 'mobile';
}
