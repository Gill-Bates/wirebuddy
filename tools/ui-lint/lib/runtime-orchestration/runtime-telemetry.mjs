//
// tools/ui-lint/lib/runtime-orchestration/runtime-telemetry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createRuntimeTelemetry() {
    return {
        startupTimeMs: 0,
        contextCreationTimeMs: 0,
        screenshotTimeMs: 0,
        pageEvaluations: 0,
        runtimeAnalyticEvents: 0,
        createdAt: new Date().toISOString(),
    };
}

export function buildRuntimeAnalytics(telemetry, extra = {}) {
    return {
        startupTimeMs: telemetry.startupTimeMs,
        contextCreationTimeMs: telemetry.contextCreationTimeMs,
        screenshotTimeMs: telemetry.screenshotTimeMs,
        pageEvaluations: telemetry.pageEvaluations,
        runtimeAnalyticEvents: telemetry.runtimeAnalyticEvents,
        ...extra,
    };
}
