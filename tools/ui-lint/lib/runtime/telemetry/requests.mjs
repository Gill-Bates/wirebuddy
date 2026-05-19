//
// tools/ui-lint/lib/runtime/telemetry/requests.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createRequestTimeline() {
    return {
        items: [],
        byId: new Map(),
        nextId: 1,
    };
}
