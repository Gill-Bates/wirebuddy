//
// tools/ui-lint/lib/dom-runtime/snapshot/rendering-snapshot.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildCompositingSnapshot } from '../rendering/compositing.mjs';
import { buildPaintOrder } from '../rendering/paint-order.mjs';

export function buildRenderingSnapshot(snapshot) {
    const paintOrder = buildPaintOrder(snapshot.nodes);

    return {
        paintOrder,
        nodes: snapshot.nodes.map((node) => {
            const compositing = buildCompositingSnapshot(node);
            return {
                stableId: node.stableId,
                rendering: {
                    visible: node.rendering.visible,
                    hidden: node.rendering.hidden,
                    clipped: node.rendering.clipped,
                    composited: compositing.composited,
                    layerHint: compositing.layerHint,
                },
            };
        }),
    };
}
