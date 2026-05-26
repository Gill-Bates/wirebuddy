//
// tools/ui-lint/lib/runtime/browser/context.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createBrowserContextOptions({ viewport = { width: 1440, height: 1100 }, storageState = null, userAgent = null } = {}) {
    const options = { viewport };
    if (storageState) options.storageState = storageState;
    if (userAgent) options.userAgent = userAgent;
    return options;
}
