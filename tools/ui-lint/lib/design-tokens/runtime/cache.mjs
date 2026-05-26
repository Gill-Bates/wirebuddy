//
// tools/ui-lint/lib/design-tokens/runtime/cache.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createTokenCache() {
    const cache = new Map();

    return {
        get(key) {
            return cache.get(key);
        },
        set(key, value) {
            cache.set(key, value);
            return value;
        },
        has(key) {
            return cache.has(key);
        },
        clear() {
            cache.clear();
        },
        entries() {
            return [...cache.entries()];
        },
    };
}