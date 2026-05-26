//
// tools/ui-lint/lib/design-tokens/themes/theme-diffing.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function flattenTokens(tokens, prefix = [], output = new Map()) {
    for (const [key, value] of Object.entries(tokens || {})) {
        const nextPath = [...prefix, key];
        if (value && typeof value === 'object' && !Array.isArray(value)) {
            flattenTokens(value, nextPath, output);
            continue;
        }
        output.set(nextPath.join('.'), value);
    }
    return output;
}

export function detectTokenDrift({ baseline = {}, current = {} } = {}) {
    const baselineMap = flattenTokens(baseline);
    const currentMap = flattenTokens(current);
    const added = [];
    const removed = [];
    const changed = [];

    for (const [path, value] of currentMap.entries()) {
        if (!baselineMap.has(path)) {
            added.push({ path, value });
            continue;
        }
        if (baselineMap.get(path) !== value) {
            changed.push({ path, before: baselineMap.get(path), after: value });
        }
    }

    for (const [path, value] of baselineMap.entries()) {
        if (!currentMap.has(path)) {
            removed.push({ path, value });
        }
    }

    return { added, removed, changed };
}