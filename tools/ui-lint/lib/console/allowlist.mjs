//
// tools/ui-lint/lib/console/allowlist.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const CONSOLE_ALLOWLIST = [
    /ResizeObserver loop/i,
    /Failed to load resource.*favicon/i,
    /DevTools failed to load/i,
    /Download the React DevTools/i,
    /React does not recognize/i,
    /Warning: Each child in a list/i,
    /Bootstrap.*deprecated/i,
    /tile.*404/i,
    /openstreetmap.*failed/i,
    /Couldn't load preload assets:\s+TypeError: Cannot read properties of null \(reading 'href'\)/i,
    /Connecting to 'data:image\/gif;base64,[^']+' violates the following Content Security Policy directive: "connect-src 'self'"/i,
];
