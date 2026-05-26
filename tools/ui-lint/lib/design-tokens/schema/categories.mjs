//
// tools/ui-lint/lib/design-tokens/schema/categories.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const TOKEN_CATEGORIES = Object.freeze([
    'spacing',
    'radius',
    'colors',
    'interaction',
    'animation',
    'breakpoints',
    'badge',
    'card',
    'modal',
    'form',
    'wcag',
]);

export const TOKEN_CATEGORY_LOOKUP = Object.freeze(new Set(TOKEN_CATEGORIES));