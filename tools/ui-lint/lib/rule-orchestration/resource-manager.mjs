//
// tools/ui-lint/lib/rule-orchestration/resource-manager.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createResourceManager(initialResources = {}) {
    const cache = new Map();
    const resources = new Map(Object.entries(initialResources).filter(([, value]) => value !== undefined));

    return {
        async acquire(name, loader) {
            if (resources.has(name)) {
                return resources.get(name);
            }
            if (cache.has(name)) {
                return cache.get(name);
            }

            const promise = Promise.resolve().then(loader);
            cache.set(name, promise);
            const value = await promise;
            resources.set(name, value);
            cache.delete(name);
            return value;
        },
        get(name) {
            return resources.get(name);
        },
        has(name) {
            return resources.has(name) || cache.has(name);
        },
        snapshot() {
            return Object.fromEntries(resources.entries());
        },
    };
}
