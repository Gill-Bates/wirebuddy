//
// tools/ui-lint/lib/design-tokens/themes/theme-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { THEME_REGISTRY, buildThemeOverlay } from './overlays.mjs';
import { detectTokenDrift } from './theme-diffing.mjs';

export function createThemeRuntime({ registry = THEME_REGISTRY, activeTheme = 'light' } = {}) {
    let currentTheme = activeTheme;

    return {
        listThemes() {
            return { ...registry };
        },
        loadTheme(themeName) {
            if (!registry[themeName]) {
                throw new Error(`Unknown theme: ${themeName}`);
            }
            currentTheme = themeName;
            return currentTheme;
        },
        getTheme() {
            return registry[currentTheme];
        },
        overlay(baseTokens, themeTokens) {
            return buildThemeOverlay(baseTokens, themeTokens);
        },
        diffThemes(baseline, current) {
            return detectTokenDrift({ baseline, current });
        },
        get activeTheme() {
            return currentTheme;
        },
    };
}