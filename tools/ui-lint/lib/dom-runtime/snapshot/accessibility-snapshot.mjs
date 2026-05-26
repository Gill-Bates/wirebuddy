//
// tools/ui-lint/lib/dom-runtime/snapshot/accessibility-snapshot.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildAccessibilitySnapshot(snapshot) {
    return {
        nodes: snapshot.nodes.map((node) => ({
            stableId: node.stableId,
            accessibility: node.accessibility,
        })),
        counts: {
            focusable: snapshot.nodes.filter((node) => node.accessibility.focusable).length,
            interactive: snapshot.nodes.filter((node) => node.interaction.interactive).length,
        },
    };
}
