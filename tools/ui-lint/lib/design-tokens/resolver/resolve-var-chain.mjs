//
// tools/ui-lint/lib/design-tokens/resolver/resolve-var-chain.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const MAX_RESOLUTION_DEPTH = 64;
const CSS_CUSTOM_PROPERTY_REFERENCE_RE = /^--[A-Za-z0-9_-]+$/;

function createScanState() {
    return {
        escaped: false,
        inSingleQuote: false,
        inDoubleQuote: false,
    };
}

function consumeQuotedOrEscapedCharacter(state, character) {
    if (state.escaped) {
        state.escaped = false;
        return true;
    }

    if (state.inSingleQuote) {
        if (character === '\\') {
            state.escaped = true;
            return true;
        }

        if (character === "'") {
            state.inSingleQuote = false;
        }
        return true;
    }

    if (state.inDoubleQuote) {
        if (character === '\\') {
            state.escaped = true;
            return true;
        }

        if (character === '"') {
            state.inDoubleQuote = false;
        }
        return true;
    }

    if (character === '\\') {
        state.escaped = true;
        return true;
    }

    if (character === "'") {
        state.inSingleQuote = true;
        return true;
    }

    if (character === '"') {
        state.inDoubleQuote = true;
        return true;
    }

    return false;
}

function findVarFunctionStart(text, startIndex) {
    const scanState = createScanState();

    for (let index = startIndex; index < text.length; index += 1) {
        const character = text[index];
        if (consumeQuotedOrEscapedCharacter(scanState, character)) {
            continue;
        }

        if (text.startsWith('var(', index)) {
            return index;
        }
    }

    return -1;
}

function findClosingParen(text, openIndex) {
    let depth = 1;
    const scanState = createScanState();

    for (let index = openIndex + 1; index < text.length; index += 1) {
        const character = text[index];
        if (consumeQuotedOrEscapedCharacter(scanState, character)) {
            continue;
        }

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
    const scanState = createScanState();

    for (const character of text) {
        const handledByScanState = consumeQuotedOrEscapedCharacter(scanState, character);

        if (!handledByScanState && character === '(') depth += 1;
        if (!handledByScanState && character === ')') depth -= 1;
        if (!handledByScanState && character === ',' && depth === 0) {
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

function serializeResolvedValue(value) {
    if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
        return String(value);
    }

    throw new TypeError('resolver must return a primitive string, number, boolean, or bigint value');
}

function resolveText(text, resolver, context, trail, resolutionState) {
    const chunks = [];
    let cursor = 0;

    while (cursor < text.length) {
        const startIndex = findVarFunctionStart(text, cursor);
        if (startIndex === -1) {
            chunks.push(text.slice(cursor));
            break;
        }

        chunks.push(text.slice(cursor, startIndex));
        const openParenIndex = startIndex + 3;
        const bodyEnd = findClosingParen(text, openParenIndex);
        if (bodyEnd === -1) {
            resolutionState.unresolved = true;
            chunks.push(text.slice(startIndex));
            break;
        }

        const callText = text.slice(openParenIndex + 1, bodyEnd);
        const [referenceName, fallbackValue] = splitTopLevelArguments(callText);
        const resolved = resolver(referenceName, context, trail);
        if (resolved?.unresolved || resolved?.circular || resolved?.invalid || resolved?.depthLimit) {
            resolutionState.unresolved = true;
        }

        if (resolved?.value != null && resolved.value !== '') {
            chunks.push(serializeResolvedValue(resolved.value));
        } else if (fallbackValue != null) {
            chunks.push(resolveText(fallbackValue, resolver, context, trail, resolutionState));
        } else {
            resolutionState.unresolved = true;
        }

        cursor = bodyEnd + 1;
    }

    return chunks.join('');
}

export function resolveVarChain(value, resolver, context = {}, trail = new Set()) {
    if (typeof value !== 'string') {
        return { value, unresolved: false, references: [] };
    }

    const references = new Set();
    const resolutionState = { unresolved: false };
    const wrappedResolver = (referenceName, nextContext, nextTrail) => {
        const normalizedName = String(referenceName || '').trim();
        if (!normalizedName) {
            resolutionState.unresolved = true;
            return { value: '', unresolved: true };
        }

        if (!CSS_CUSTOM_PROPERTY_REFERENCE_RE.test(normalizedName)) {
            resolutionState.unresolved = true;
            return { value: '', invalid: true, unresolved: true };
        }

        references.add(normalizedName);
        const activeTrail = nextTrail instanceof Set ? nextTrail : trail;
        if (activeTrail.size >= MAX_RESOLUTION_DEPTH) {
            resolutionState.unresolved = true;
            return { value: '', depthLimit: true, unresolved: true };
        }

        if (activeTrail.has(normalizedName)) {
            resolutionState.unresolved = true;
            return { value: '', circular: true, unresolved: true };
        }

        const nextTrailSet = new Set(activeTrail);
        nextTrailSet.add(normalizedName);
        return resolver(normalizedName, nextContext, nextTrailSet);
    };

    const resolvedValue = resolveText(value, wrappedResolver, context, trail, resolutionState);
    return {
        value: resolvedValue,
        unresolved: resolutionState.unresolved,
        references: [...references],
    };
}