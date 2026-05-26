//
// tools/ui-lint/lib/config/themes/themes.mjs
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

export const CONTRAST_MODES = deepFreeze({
    NORMAL: 'normal',
    HIGH: 'high',
});

const RESERVED_THEME_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const themeRegistryStore = Object.create(null);

export let THEME_REGISTRY = Object.freeze(Object.create(null));
export let THEMES = Object.freeze([]);

function validateThemeName(name) {
    if (typeof name !== 'string') {
        throw new TypeError(`Theme name must be a string, got ${typeof name}`);
    }

    const normalized = name.trim();
    if (!normalized) {
        throw new TypeError('Theme name must not be empty');
    }
    if (RESERVED_THEME_KEYS.has(normalized)) {
        throw new TypeError(`Theme name is reserved: ${normalized}`);
    }
    if (!/^[A-Za-z][A-Za-z0-9_-]*$/.test(normalized)) {
        throw new TypeError(`Theme name contains unsupported characters: ${normalized}`);
    }

    return normalized;
}

function validateThemeDefinition(definition) {
    if (!definition || typeof definition !== 'object' || Array.isArray(definition)) {
        throw new TypeError('Theme definition must be a plain object');
    }

    if ('label' in definition && (typeof definition.label !== 'string' || definition.label.trim() === '')) {
        throw new TypeError('Theme definition.label must be a non-empty string');
    }
    if ('dataAttr' in definition && (typeof definition.dataAttr !== 'string' || definition.dataAttr.trim() === '')) {
        throw new TypeError('Theme definition.dataAttr must be a non-empty string');
    }
    if ('contrast' in definition && !Object.values(CONTRAST_MODES).includes(definition.contrast)) {
        throw new TypeError(`Theme definition.contrast must be one of ${Object.values(CONTRAST_MODES).join(', ')}`);
    }

    return definition;
}

function createThemeDefinition(name, definition = {}) {
    const validatedName = validateThemeName(name);
    const validatedDefinition = validateThemeDefinition(definition);
    return deepFreeze({
        label: validatedName,
        dataAttr: validatedName,
        contrast: CONTRAST_MODES.NORMAL,
        ...validatedDefinition,
    });
}

function syncThemeExports() {
    const snapshot = Object.create(null);
    for (const [name, definition] of Object.entries(themeRegistryStore)) {
        snapshot[name] = definition;
    }

    THEME_REGISTRY = Object.freeze(snapshot);
    THEMES = Object.freeze(Object.keys(snapshot));
}

function installTheme(name, definition) {
    const normalizedName = validateThemeName(name);
    if (Object.hasOwn(themeRegistryStore, normalizedName)) {
        throw new Error(`Theme "${normalizedName}" already exists`);
    }

    const themeDefinition = createThemeDefinition(normalizedName, definition);
    themeRegistryStore[normalizedName] = themeDefinition;
    syncThemeExports();
    return themeDefinition;
}

installTheme('light', { label: 'Light', dataAttr: 'light', contrast: CONTRAST_MODES.NORMAL });
installTheme('dark', { label: 'Dark', dataAttr: 'dark', contrast: CONTRAST_MODES.NORMAL });
installTheme('highContrast', { label: 'High Contrast', dataAttr: 'high-contrast', contrast: CONTRAST_MODES.HIGH });

export function registerTheme(name, definition = {}) {
    return installTheme(name, definition);
}

export function getThemeRegistry() {
    return THEME_REGISTRY;
}