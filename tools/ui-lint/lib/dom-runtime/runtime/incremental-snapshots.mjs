//
// tools/ui-lint/lib/dom-runtime/runtime/incremental-snapshots.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildIncrementalSnapshot(current, previous = null) {
    if (!previous) {
        return { added: current.nodes, removed: [], changed: [] };
    }

    const previousById = new Map(previous.nodes.map((node) => [node.stableId, node]));
    const currentById = new Map(current.nodes.map((node) => [node.stableId, node]));
    const added = [];
    const removed = [];
    const changed = [];

    for (const [stableId, node] of currentById.entries()) {
        if (!previousById.has(stableId)) {
            added.push(node);
            continue;
        }
        const before = previousById.get(stableId);
        if (JSON.stringify(before) !== JSON.stringify(node)) {
            changed.push({ before, after: node });
        }
    }

    for (const [stableId, node] of previousById.entries()) {
        if (!currentById.has(stableId)) {
            removed.push(node);
        }
    }

    return { added, removed, changed };
}
