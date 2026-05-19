//
// tools/ui-lint/lib/orchestration/telemetry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createAuditTelemetry({ browser = null, scope = null, ruleId = null, category = null } = {}) {
    return {
        browser,
        scope,
        ruleId,
        category,
        startedAt: Date.now(),
        durationMs: 0,
        cpuCost: 0,
        findings: 0,
        skipped: false,
    };
}

export function finalizeAuditTelemetry(telemetry, { findings = [], skipped = false, cpuCost = 0 } = {}) {
    return {
        ...telemetry,
        durationMs: Date.now() - telemetry.startedAt,
        cpuCost,
        findings: findings.length,
        skipped,
    };
}
