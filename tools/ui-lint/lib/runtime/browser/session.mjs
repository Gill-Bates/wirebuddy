//
// tools/ui-lint/lib/runtime/browser/session.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createBrowserSession(page, metadata = {}) {
    return {
        page,
        metadata,
        createdAt: Date.now(),
    };
}
