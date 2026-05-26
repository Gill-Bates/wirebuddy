//
// tools/ui-lint/lib/design-tokens/resolver/resolve-token.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { evaluateDimension, evaluateDuration } from './evaluate-units.mjs';
import { resolveVarChain } from './resolve-var-chain.mjs';

function readTokenEntry(index, tokenName, theme = 'base') {
    const themeEntries = index.get(tokenName);
    return themeEntries?.get(theme) || themeEntries?.get('base') || themeEntries?.get('*') || null;
}

export function resolveToken(tokenName, { index, theme = 'base', fallback, required = false, type = 'string', context = {}, trail = new Set() } = {}) {
    if (!index || typeof index.get !== 'function') {
        throw new TypeError('index must be a token index Map');
    }

    const entry = readTokenEntry(index, tokenName, theme);
    const hasValue = entry?.value != null && entry.value !== '';

    if (!hasValue && required) {
        throw new Error(`Missing required token: ${tokenName}`);
    }

    const rawValue = hasValue ? entry.value : fallback;
    const resolver = (referenceName, nextContext, nextTrail = trail) => resolveToken(referenceName, {
        index,
        theme,
        fallback: '',
        required: false,
        type,
        context: nextContext,
        trail: nextTrail,
    });

    const resolution = typeof rawValue === 'string'
        ? resolveVarChain(rawValue, resolver, context, trail)
        : { value: rawValue, references: [], unresolved: false };

    let computedValue = resolution.value;
    if (type === 'dimension') {
        computedValue = evaluateDimension(resolution.value, { ...context, resolveToken: resolver });
    } else if (type === 'duration') {
        computedValue = evaluateDuration(resolution.value, { ...context, resolveToken: resolver });
    } else if (type === 'number') {
        const numericValue = Number.parseFloat(resolution.value);
        computedValue = Number.isNaN(numericValue) ? 0 : numericValue;
    }

    return {
        value: computedValue,
        rawValue,
        source: entry?.source || null,
        selector: entry?.selector || null,
        theme,
        category: entry?.category || null,
        type,
        computed: true,
        fallbackUsed: !hasValue,
        deprecated: Boolean(entry?.deprecated),
        references: resolution.references,
        unresolved: resolution.unresolved,
    };
}