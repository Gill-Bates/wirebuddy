//
// tools/ui-lint/lib/rule-orchestration/telemetry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { normalizeSeverity } from './severity-normalizer.mjs';

export function createRuleTelemetry() {
    return {
        executionCount: 0,
        failureCount: 0,
        skipCount: 0,
        totalDurationMs: 0,
        lastDurationMs: 0,
        avgDurationMs: 0,
        lastRunAt: null,
        lastStatus: 'idle',
        lastError: null,
        pageEvaluations: 0,
        domReads: 0,
        memoryDeltaBytes: 0,
        health: 'stable',
        failureRate: 0,
    };
}

export function finalizeRuleTelemetry(telemetry, snapshot) {
    telemetry.executionCount += 1;
    telemetry.lastDurationMs = snapshot.durationMs;
    telemetry.totalDurationMs += snapshot.durationMs;
    telemetry.avgDurationMs = telemetry.totalDurationMs / telemetry.executionCount;
    telemetry.lastRunAt = snapshot.finishedAt;
    telemetry.lastStatus = snapshot.status;
    telemetry.lastError = snapshot.error || null;
    telemetry.pageEvaluations += snapshot.pageEvaluations || 0;
    telemetry.domReads += snapshot.domReads || 0;
    telemetry.memoryDeltaBytes += snapshot.memoryDeltaBytes || 0;
    telemetry.failureCount += snapshot.status === 'failed' ? 1 : 0;
    telemetry.skipCount += snapshot.status === 'skipped' ? 1 : 0;
    telemetry.failureRate = telemetry.executionCount === 0 ? 0 : telemetry.failureCount / telemetry.executionCount;
    telemetry.health = telemetry.failureRate > 0.25 ? 'unstable' : telemetry.failureRate > 0.05 ? 'flaky' : 'stable';
    telemetry.normalizedSeverity = normalizeSeverity(snapshot.severity || 'warning');
    return telemetry;
}

export function classifyFailure(error) {
    const message = String(error?.message || error || '');
    const lower = message.toLowerCase();
    if (lower.includes('timeout') || lower.includes('etimedout')) return 'retryable';
    if (lower.includes('closed') || lower.includes('disconnected') || lower.includes('econnreset')) return 'flaky';
    return 'fatal';
}
