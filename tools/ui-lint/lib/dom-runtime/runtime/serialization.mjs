//
// tools/ui-lint/lib/dom-runtime/runtime/serialization.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function serializeCompact(snapshot) {
    return {
        schemaVersion: snapshot.schemaVersion,
        viewport: snapshot.viewport,
        collections: snapshot.collections,
        counts: snapshot.counts,
    };
}

export function serializeVerbose(snapshot) {
    return structuredClone(snapshot);
}
