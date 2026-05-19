//
// tools/ui-lint/lib/dom-runtime/runtime/stable-ids.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildStableId(node) {
    const domPath = node.domPath || [];
    const semanticRole = node.accessibility?.computedRole || node.role || 'unknown';
    const textFingerprint = String(node.text || '').slice(0, 48).toLowerCase();
    return [domPath.join('>'), semanticRole, textFingerprint].join('|');
}
