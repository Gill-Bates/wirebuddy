//
// tools/ui-lint/lib/design-tokens/parser/variable-parser.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const THEME_SELECTOR_RE = /data-(?:bs-)?theme\s*=\s*["']?([a-zA-Z0-9-_]+)["']?/i;

export function collectTokenDeclarations(root) {
    const declarations = [];

    root.walkDecls((declaration) => {
        if (!declaration.prop?.startsWith('--')) return;

        const rule = declaration.parent?.type === 'rule' ? declaration.parent : null;
        const selector = rule?.selector || ':root';
        declarations.push({
            name: declaration.prop,
            value: declaration.value,
            selector,
            theme: extractThemeName(selector),
            source: declaration.source?.input?.file || null,
            line: declaration.source?.start?.line || null,
            column: declaration.source?.start?.column || null,
        });
    });

    return declarations;
}

export function buildTokenIndex(declarations) {
    const index = new Map();

    for (const declaration of declarations) {
        const themeKey = declaration.theme || 'base';
        if (!index.has(declaration.name)) {
            index.set(declaration.name, new Map());
        }
        index.get(declaration.name).set(themeKey, declaration);
    }

    return index;
}

export function extractThemeName(selector) {
    const match = THEME_SELECTOR_RE.exec(selector || '');
    return match?.[1] || 'base';
}