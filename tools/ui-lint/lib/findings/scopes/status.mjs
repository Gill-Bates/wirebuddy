//
// tools/ui-lint/lib/findings/scopes/status.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function isStatusScope(context) {
    return context.scope === 'status';
}

export function isExpectedStatusUnavailable(view, response) {
    if (view.scope !== 'status' || !response) return false;
    try {
        return new URL(response.url()).pathname === '/status' && response.status() === 404;
    } catch {
        return false;
    }
}
