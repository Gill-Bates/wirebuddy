//
// tools/ui-lint/lib/runtime-orchestration/runtime-policies.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const ENVIRONMENTS = Object.freeze(['local', 'ci', 'nightly', 'regression']);

export function validateRuntimePolicy(policy) {
    if (!policy || typeof policy !== 'object') {
        throw new Error('Runtime policy must be an object');
    }

    return {
        ...policy,
        maxParallelPages: Number.isInteger(policy.maxParallelPages) ? policy.maxParallelPages : 4,
        retryFlakyRules: Boolean(policy.retryFlakyRules ?? true),
        timeoutMultiplier: typeof policy.timeoutMultiplier === 'number' ? policy.timeoutMultiplier : 1.5,
    };
}

export function buildEnvironmentPolicy(environment) {
    if (!ENVIRONMENTS.includes(environment)) {
        return { environment: 'local', profileDepth: 'standard', archivalMode: 'preserve-on-failure' };
    }

    if (environment === 'ci') {
        return { environment, profileDepth: 'full', archivalMode: 'preserve-on-failure' };
    }

    if (environment === 'nightly') {
        return { environment, profileDepth: 'full', archivalMode: 'archive-all' };
    }

    if (environment === 'regression') {
        return { environment, profileDepth: 'full', archivalMode: 'archive-all' };
    }

    return { environment, profileDepth: 'standard', archivalMode: 'preserve-on-failure' };
}
