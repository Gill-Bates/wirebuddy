//
// tools/ui-lint/lib/findings/scopes/dns.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function isDnsScope(context) {
    return context.scope === 'dns';
}

export function isDesktopDnsScope(context) {
    return isDnsScope(context) && context.device === 'desktop';
}
