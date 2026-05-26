//
// tools/ui-lint/lib/design-tokens/parser/css-parser.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import postcss from 'postcss';

import { normalizeCssAst } from './ast-normalizer.mjs';

export function parseDesignTokens(cssText, { from = 'tokens.css' } = {}) {
    const root = postcss.parse(String(cssText ?? ''), { from });
    return normalizeCssAst(root);
}