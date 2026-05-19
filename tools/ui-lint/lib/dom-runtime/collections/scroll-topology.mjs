//
// tools/ui-lint/lib/dom-runtime/collections/scroll-topology.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildScrollTopology(nodes) {
    const rootScroller = nodes.find((node) => node.isRootScroller) || null;
    const nestedScrollers = nodes.filter((node) => node.scrollable && !node.isRootScroller);
    const chains = nestedScrollers.map((node) => node.scrollChain || []);

    return {
        rootScroller,
        nestedScrollers,
        chains,
    };
}
