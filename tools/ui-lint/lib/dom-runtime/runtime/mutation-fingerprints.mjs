//
// tools/ui-lint/lib/dom-runtime/runtime/mutation-fingerprints.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildMutationFingerprint(node) {
    return [
        node.tag,
        node.id || '',
        node.role || '',
        node.text || '',
        node.className || '',
        node.style?.display || '',
        node.style?.visibility || '',
    ].join('|');
}
