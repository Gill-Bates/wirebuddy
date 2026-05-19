//
// tools/ui-lint/lib/config/themes/themes.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const THEME_REGISTRY = {
    light: Object.freeze({ label: 'Light', dataAttr: 'light', contrast: 'normal' }),
    dark: Object.freeze({ label: 'Dark', dataAttr: 'dark', contrast: 'normal' }),
    highContrast: Object.freeze({ label: 'High Contrast', dataAttr: 'high-contrast', contrast: 'high' }),
};

export const THEMES = Object.freeze(Object.keys(THEME_REGISTRY));

export function registerTheme(name, definition) {
    THEME_REGISTRY[name] = Object.freeze({ label: name, dataAttr: name, contrast: 'normal', ...definition });
    return THEME_REGISTRY[name];
}

export function getThemeRegistry() {
    return { ...THEME_REGISTRY };
}