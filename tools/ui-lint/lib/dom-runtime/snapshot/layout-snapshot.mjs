//
// tools/ui-lint/lib/dom-runtime/snapshot/layout-snapshot.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildLayoutSnapshot(snapshot) {
    return {
        viewport: snapshot.viewport,
        visualViewport: snapshot.visualViewport,
        contentRoot: snapshot.contentRoot,
        nodes: snapshot.nodes.map((node) => ({
            stableId: node.stableId,
            domPath: node.domPath,
            geometry: node.rect,
            clipping: node.clipping,
            stacking: node.stacking,
        })),
    };
}
