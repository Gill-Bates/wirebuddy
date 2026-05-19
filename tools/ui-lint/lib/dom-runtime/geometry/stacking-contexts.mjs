//
// tools/ui-lint/lib/dom-runtime/geometry/stacking-contexts.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildStackingContexts(nodes) {
    return nodes.map((node) => ({
        stableId: node.stableId,
        root: Boolean(node.isRootContext),
        zIndex: node.style?.zIndex || 'auto',
        isolation: node.style?.isolation || 'auto',
        opacity: node.style?.opacity || '1',
    }));
}
