//
// tools/ui-lint/lib/config/tokens/schema.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }

    Object.freeze(value);
    for (const nested of Object.values(value)) {
        deepFreeze(nested);
    }
    return value;
}

export const TOKEN_CATEGORY_REGISTRY = deepFreeze({
    ACCESSIBILITY: 'accessibility',
    COMPONENTS: 'components',
    GENERAL: 'general',
    LAYOUT: 'layout',
    MOTION: 'motion',
    RUNTIME: 'runtime',
    SCREENSHOTS: 'screenshots',
    THEMES: 'themes',
});

export const TOKEN_SCHEMA = deepFreeze({
    version: 1,
    minimumSupportedVersion: 1,
});

export const TOKEN_SCHEMA_VERSION = TOKEN_SCHEMA.version;
export const TOKEN_CATEGORIES = Object.freeze(Object.values(TOKEN_CATEGORY_REGISTRY));
export const TOKEN_CATEGORY_LOOKUP = Object.freeze(new Set(TOKEN_CATEGORIES));

export function isValidTokenCategory(category) {
    return typeof category === 'string' && TOKEN_CATEGORY_LOOKUP.has(category);
}