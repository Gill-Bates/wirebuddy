//
// tools/ui-lint/lib/design-tokens/providers/json-provider.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createJsonTokenProvider({ tokens = {}, name = 'json', source = 'inline-json' } = {}) {
    return {
        type: 'json',
        name,
        source,
        loadSync() {
            return {
                provider: name,
                source,
                sourceHash: null,
                declarations: [],
                index: new Map(),
                dependencyGraph: new Map(),
                circularDependencies: [],
                data: structuredClone(tokens),
            };
        },
        async load() {
            return this.loadSync();
        },
    };
}