//
// tools/ui-lint/lib/design-tokens/providers/figma-provider.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createFigmaTokenProvider({ name = 'figma', source = 'figma-export' } = {}) {
    return {
        type: 'figma',
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
                data: {},
            };
        },
        async load() {
            return this.loadSync();
        },
    };
}