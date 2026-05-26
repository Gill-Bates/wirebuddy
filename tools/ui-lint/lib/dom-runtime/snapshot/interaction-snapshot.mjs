//
// tools/ui-lint/lib/dom-runtime/snapshot/interaction-snapshot.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildInteractionSnapshot(snapshot) {
    return {
        nodes: snapshot.nodes.map((node) => ({
            stableId: node.stableId,
            interaction: node.interaction,
        })),
        collections: snapshot.collections,
    };
}
