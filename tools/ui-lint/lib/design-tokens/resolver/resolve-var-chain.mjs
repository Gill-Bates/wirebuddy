//
// tools/ui-lint/lib/design-tokens/resolver/resolve-var-chain.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function findClosingParen(text, openIndex) {
    let depth = 1;
    for (let index = openIndex + 1; index < text.length; index += 1) {
        const character = text[index];
        if (character === '(') depth += 1;
        if (character === ')') {
            depth -= 1;
            if (depth === 0) return index;
        }
    }
    return -1;
}

function splitTopLevelArguments(text) {
    const argumentsList = [];
    let current = '';
    let depth = 0;

    for (const character of text) {
        if (character === '(') depth += 1;
        if (character === ')') depth -= 1;
        if (character === ',' && depth === 0) {
            argumentsList.push(current.trim());
            current = '';
            continue;
        }
        current += character;
    }

    if (current.trim()) {
        argumentsList.push(current.trim());
    }

    return argumentsList;
}

function resolveText(text, resolver, context, trail) {
    let output = '';
    let cursor = 0;

    while (cursor < text.length) {
        const startIndex = text.indexOf('var(', cursor);
        if (startIndex === -1) {
            output += text.slice(cursor);
            break;
        }

        output += text.slice(cursor, startIndex);
        const openParenIndex = startIndex + 3;
        const bodyEnd = findClosingParen(text, openParenIndex);
        if (bodyEnd === -1) {
            output += text.slice(startIndex);
            break;
        }

        const callText = text.slice(openParenIndex + 1, bodyEnd);
        const [referenceName, fallbackValue] = splitTopLevelArguments(callText);
        const resolved = resolver(referenceName, context, trail);
        if (resolved?.value != null && resolved.value !== '') {
            output += String(resolved.value);
        } else if (fallbackValue != null) {
            output += resolveText(fallbackValue, resolver, context, trail);
        }

        cursor = bodyEnd + 1;
    }

    return output;
}

export function resolveVarChain(value, resolver, context = {}, trail = new Set()) {
    if (typeof value !== 'string') {
        return { value, unresolved: false, references: [] };
    }

    const references = [];
    const wrappedResolver = (referenceName, nextContext, nextTrail) => {
        const normalizedName = String(referenceName || '').trim();
        if (!normalizedName) return { value: '' };
        references.push(normalizedName);
        const activeTrail = nextTrail instanceof Set ? nextTrail : trail;
        if (activeTrail.has(normalizedName)) {
            return { value: '', circular: true };
        }
        const nextTrailSet = new Set(activeTrail);
        nextTrailSet.add(normalizedName);
        return resolver(normalizedName, nextContext, nextTrailSet);
    };

    const resolvedValue = resolveText(value, wrappedResolver, context, trail);
    return {
        value: resolvedValue,
        unresolved: resolvedValue === value && references.length > 0,
        references,
    };
}