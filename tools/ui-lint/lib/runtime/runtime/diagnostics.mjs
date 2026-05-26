//
// tools/ui-lint/lib/runtime/runtime/diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildRuntimeDiagnostics(runtime = {}) {
    return {
        version: runtime.version || 1,
        browser: runtime.browser || null,
        viewport: runtime.viewport || null,
        performance: runtime.performance || null,
        dom: runtime.dom || null,
        fonts: runtime.fonts || null,
        interactions: runtime.interactions || null,
    };
}
