//
// tools/ui-lint/lib/design-tokens/parser/css-parser.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { loadDep } from '../../deps.mjs';
import { normalizeCssAst } from './ast-normalizer.mjs';

const { default: postcss } = await loadDep('postcss');

export function parseDesignTokens(cssText, { from = 'tokens.css' } = {}) {
    const root = postcss.parse(String(cssText ?? ''), { from });
    return normalizeCssAst(root);
}