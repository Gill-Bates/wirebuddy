//
// tools/ui-lint/lib/findings/scopes/users.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function isUsersScope(context) {
    return context.scope === 'users';
}

export function isMobileUsersScope(context) {
    return isUsersScope(context) && context.device === 'mobile';
}
