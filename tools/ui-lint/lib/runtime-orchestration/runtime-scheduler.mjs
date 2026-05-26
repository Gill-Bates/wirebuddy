//
// tools/ui-lint/lib/runtime-orchestration/runtime-scheduler.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { validateRuntimePolicy } from './runtime-policies.mjs';

export function createRuntimeScheduler(profile) {
    const executionPolicy = validateRuntimePolicy(profile.executionPolicy || {});

    return {
        profile: profile.name,
        executionPolicy,
        optimize(runtimes = []) {
            return [...runtimes].sort((left, right) => {
                const leftCost = left.cost || 'medium';
                const rightCost = right.cost || 'medium';
                if (leftCost !== rightCost) return leftCost.localeCompare(rightCost);
                return String(left.runtimeId).localeCompare(String(right.runtimeId));
            });
        },
        parallelizationStrategy: executionPolicy.maxParallelPages > 2 ? 'adaptive' : 'conservative',
    };
}
