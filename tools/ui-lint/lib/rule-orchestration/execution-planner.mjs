//
// tools/ui-lint/lib/rule-orchestration/execution-planner.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const PRIORITY_ORDER = new Map([
    ['critical', 0],
    ['standard', 1],
    ['deferred', 2],
]);

const COST_ORDER = new Map([
    ['low', 0],
    ['medium', 1],
    ['high', 2],
]);

function normalizeArray(value) {
    return Array.isArray(value) ? value.filter(Boolean) : [];
}

function sortRuleEntries(left, right) {
    const priorityDelta = (PRIORITY_ORDER.get(left.meta.priority || 'standard') ?? 1) - (PRIORITY_ORDER.get(right.meta.priority || 'standard') ?? 1);
    if (priorityDelta) return priorityDelta;

    const costDelta = (COST_ORDER.get(left.meta.cost || left.meta.performanceCost || 'medium') ?? 1) - (COST_ORDER.get(right.meta.cost || right.meta.performanceCost || 'medium') ?? 1);
    if (costDelta) return costDelta;

    const confidenceDelta = (right.meta.confidence ?? 0.8) - (left.meta.confidence ?? 0.8);
    if (confidenceDelta) return confidenceDelta;

    return left.id.localeCompare(right.id);
}

function isCompatibleWithContext(ruleMeta, context) {
    const { browser, device, environment } = context;

    if (browser && ruleMeta.browsers.length && !ruleMeta.browsers.includes(browser)) {
        return false;
    }
    if (device && ruleMeta.devices.length && !ruleMeta.devices.includes(device)) {
        return false;
    }
    if (environment && ruleMeta.environments.length && !ruleMeta.environments.includes(environment)) {
        return false;
    }

    return true;
}

function collectDependencyClosure(ruleIds, registry, collected = new Map(), unresolved = new Set()) {
    for (const ruleId of ruleIds) {
        if (collected.has(ruleId)) continue;
        const rule = registry.rules.get(ruleId);
        if (!rule) {
            unresolved.add(ruleId);
            continue;
        }

        collected.set(ruleId, rule);
        collectDependencyClosure(rule.meta.dependencies || [], registry, collected, unresolved);
    }

    return { collected, unresolved };
}

function pruneRulesWithMissingDependencies(ruleMap) {
    const executable = new Map(ruleMap);
    const skipped = [];
    let changed = true;

    while (changed) {
        changed = false;
        for (const [ruleId, rule] of executable.entries()) {
            const missing = normalizeArray(rule.meta.dependencies).filter((dependencyId) => !executable.has(dependencyId));
            if (missing.length) {
                executable.delete(ruleId);
                skipped.push({ ruleId, reason: 'missingDependency', missing });
                changed = true;
            }
        }
    }

    return { executable, skipped };
}

function buildBatches(executableRules) {
    const remaining = new Map(executableRules);
    const indegree = new Map();
    const dependents = new Map();

    for (const [ruleId, rule] of remaining.entries()) {
        indegree.set(ruleId, 0);
        dependents.set(ruleId, []);
    }

    for (const [ruleId, rule] of remaining.entries()) {
        for (const dependencyId of normalizeArray(rule.meta.dependencies)) {
            if (!remaining.has(dependencyId)) continue;
            indegree.set(ruleId, (indegree.get(ruleId) || 0) + 1);
            dependents.get(dependencyId).push(ruleId);
        }
    }

    const batches = [];
    const ready = [...remaining.values()].filter((rule) => (indegree.get(rule.id) || 0) === 0).sort(sortRuleEntries);
    const visited = new Set();

    while (ready.length) {
        const level = [];
        while (ready.length) {
            const rule = ready.shift();
            if (visited.has(rule.id)) continue;
            visited.add(rule.id);
            level.push(rule);
        }

        if (!level.length) break;

        const parallelBatch = [];
        for (const rule of level) {
            const isSerial = rule.meta.executionMode === 'serial' || (rule.meta.cost || rule.meta.performanceCost) === 'high';
            if (isSerial) {
                if (parallelBatch.length) {
                    batches.push(parallelBatch.splice(0, parallelBatch.length));
                }
                batches.push([rule]);
                continue;
            }
            parallelBatch.push(rule);
        }

        if (parallelBatch.length) {
            batches.push([...parallelBatch]);
        }

        for (const rule of level) {
            for (const dependentId of dependents.get(rule.id) || []) {
                const nextDegree = (indegree.get(dependentId) || 0) - 1;
                indegree.set(dependentId, nextDegree);
                if (nextDegree === 0) {
                    const dependentRule = remaining.get(dependentId);
                    if (dependentRule && !visited.has(dependentId)) {
                        ready.push(dependentRule);
                        ready.sort(sortRuleEntries);
                    }
                }
            }
        }
    }

    const plannedRuleIds = batches.flat().map((rule) => rule.id);
    const missing = [...remaining.keys()].filter((ruleId) => !plannedRuleIds.includes(ruleId));
    if (missing.length) {
        batches.push(missing.map((ruleId) => remaining.get(ruleId)).filter(Boolean));
    }

    return batches;
}

export function planExecution(ruleIds, registry, context) {
    const requestedRuleIds = normalizeArray(ruleIds).length ? normalizeArray(ruleIds) : [...registry.rules.keys()];
    const { collected, unresolved } = collectDependencyClosure(requestedRuleIds, registry);

    const activeRules = new Map();
    const skipped = [];
    for (const [ruleId, rule] of collected.entries()) {
        if (isCompatibleWithContext(rule.meta, context)) {
            activeRules.set(ruleId, rule);
        } else {
            skipped.push({ ruleId, reason: 'inactive', meta: rule.meta });
        }
    }

    const { executable, skipped: dependencySkips } = pruneRulesWithMissingDependencies(activeRules);
    skipped.push(...dependencySkips);

    const batches = buildBatches(executable);
    const executionGraph = batches.map((batch, index) => ({
        batch: index + 1,
        ruleIds: batch.map((rule) => rule.id),
        executionMode: batch.length === 1 ? batch[0].meta.executionMode : 'parallel',
        cost: batch.length === 1 ? (batch[0].meta.cost || batch[0].meta.performanceCost || 'medium') : 'mixed',
    }));

    return {
        requestedRuleIds,
        activeRuleIds: [...executable.keys()],
        unresolvedDependencies: [...unresolved],
        skipped,
        batches,
        executionGraph,
        plannedRuleIds: executionGraph.flatMap((entry) => entry.ruleIds),
    };
}

export { sortRuleEntries, isCompatibleWithContext };
