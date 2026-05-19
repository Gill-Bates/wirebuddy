//
// tools/ui-lint/lib/dom-runtime/geometry/clipping.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildClippingSnapshot(node) {
    return {
        clippingAncestors: node.clippingAncestors || node.clipping?.clippingAncestors || [],
        overflowChain: node.overflowChain || node.clipping?.overflowChain || [],
    };
}
