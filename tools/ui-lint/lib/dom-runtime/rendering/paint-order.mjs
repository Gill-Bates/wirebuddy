//
// tools/ui-lint/lib/dom-runtime/rendering/paint-order.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildPaintOrder(nodes) {
    return nodes.map((node, index) => ({
        stableId: node.stableId,
        paintOrderIndex: index,
    }));
}
