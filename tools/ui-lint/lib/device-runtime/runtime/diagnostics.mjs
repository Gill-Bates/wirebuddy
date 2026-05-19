//
// tools/ui-lint/lib/device-runtime/runtime/diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildRuntimeDiagnostics(runtime) {
    const issues = [];

    if (!runtime?.descriptor) {
        issues.push('missing-descriptor');
    }
    if (!runtime?.browser) {
        issues.push('missing-browser');
    }
    if (runtime?.capabilities?.viewportSegments > 1 && !runtime?.foldable) {
        issues.push('missing-foldable-geometry');
    }
    if (runtime?.viewport?.layout?.width <= 0 || runtime?.viewport?.layout?.height <= 0) {
        issues.push('invalid-viewport');
    }

    return {
        issues,
        unsupportedCapabilities: runtime?.unsupportedCapabilities || [],
        conflictingConfigs: runtime?.conflictingConfigs || [],
        invalidViewportCombinations: runtime?.invalidViewportCombinations || [],
        missingBrowserEngines: runtime?.missingBrowserEngines || [],
    };
}