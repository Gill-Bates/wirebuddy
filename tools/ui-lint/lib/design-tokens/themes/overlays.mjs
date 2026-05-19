//
// tools/ui-lint/lib/design-tokens/themes/overlays.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const THEME_REGISTRY = Object.freeze({
    light: Object.freeze({ name: 'light', label: 'Light', inherits: null }),
    dark: Object.freeze({ name: 'dark', label: 'Dark', inherits: 'light' }),
    highContrast: Object.freeze({ name: 'highContrast', label: 'High Contrast', inherits: 'light' }),
});

export function registerThemeOverlay(registry, name, overlay) {
    registry[name] = { name, ...overlay };
    return registry[name];
}

export function buildThemeOverlay(baseTokens, themeTokens = {}) {
    return deepMerge(structuredClone(baseTokens), themeTokens);
}

function deepMerge(target, source) {
    for (const [key, value] of Object.entries(source || {})) {
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            target[key] = deepMerge(target[key] && typeof target[key] === 'object' ? target[key] : {}, value);
            continue;
        }
        target[key] = value;
    }
    return target;
}