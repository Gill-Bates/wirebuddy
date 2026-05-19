//
// tools/ui-lint/lib/console/filters.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { CONSOLE_ALLOWLIST } from './allowlist.mjs';

function getConsoleSignature(entry) {
    return [
        entry.text,
        entry.sourceURL,
        entry.url,
        entry.stack,
        entry.location,
    ]
        .filter(Boolean)
        .map((value) => String(value))
        .join('\n');
}

export function filterConsoleEntries(entries, { allowlist = CONSOLE_ALLOWLIST } = {}) {
    return entries.filter((entry) => {
        const signature = getConsoleSignature(entry);
        return !allowlist.some((pattern) => pattern.test(signature));
    });
}
