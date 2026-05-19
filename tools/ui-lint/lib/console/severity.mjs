//
// tools/ui-lint/lib/console/severity.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const CONSOLE_SEVERITY = {
    error: 3,
    warning: 2,
    info: 1,
    log: 0,
};

export function scoreConsoleSeverity(entries) {
    let score = 0;
    const critical = [];
    const serious = [];
    const minor = [];

    for (const entry of entries) {
        const severity = CONSOLE_SEVERITY[entry.type] || 0;
        score += severity;

        if (severity >= 3) {
            critical.push(entry);
        } else if (severity >= 2) {
            serious.push(entry);
        } else if (severity >= 1) {
            minor.push(entry);
        }
    }

    return { score, critical, serious, minor, total: entries.length };
}
