//
// tools/ui-lint/lib/design-tokens/schema/token-schema.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const TOKEN_SCHEMA_VERSION = 1;

export const TOKEN_SCHEMA = Object.freeze({
    spacing: Object.freeze({ xs: 'dimension', sm: 'dimension', md: 'dimension', lg: 'dimension', xl: 'dimension' }),
    radius: Object.freeze({ none: 'dimension', sm: 'dimension', md: 'dimension', lg: 'dimension', pill: 'dimension' }),
    colors: Object.freeze({ danger: 'color', warning: 'color', success: 'color', info: 'color' }),
    interaction: Object.freeze({
        touchTargetMin: 'dimension',
        touchTargetMinMobile: 'dimension',
        touchTargetMinTablet: 'dimension',
        touchTargetMinDesktop: 'dimension',
        touchTargetComfortable: 'dimension',
        focusRingWidth: 'dimension',
    }),
    animation: Object.freeze({ fast: 'duration', base: 'duration', slow: 'duration' }),
    breakpoints: Object.freeze({ sm: 'dimension', md: 'dimension', lg: 'dimension', xl: 'dimension', xxl: 'dimension' }),
    badge: Object.freeze({ paddingY: 'string', paddingX: 'string', radius: 'dimension', fontSize: 'string', fontWeight: 'string' }),
    card: Object.freeze({ padding: 'dimension', radius: 'dimension', borderWidth: 'dimension' }),
    modal: Object.freeze({ backdropBlur: 'dimension', backdropOpacity: 'number', radius: 'dimension', padding: 'dimension' }),
    form: Object.freeze({ inputHeight: 'dimension', inputRadius: 'dimension', switchHeight: 'dimension' }),
    wcag: Object.freeze({ contrastAA: 'number', contrastAALarge: 'number', contrastAAA: 'number', contrastAAALarge: 'number' }),
});