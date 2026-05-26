//
// tools/ui-lint/lib/design-tokens/runtime/snapshots.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createTokenSnapshot(snapshot) {
    return deepFreeze(structuredClone(snapshot));
}

function deepFreeze(value) {
    if (!value || typeof value !== 'object' || Object.isFrozen(value)) {
        return value;
    }

    Object.freeze(value);
    for (const nestedValue of Object.values(value)) {
        deepFreeze(nestedValue);
    }
    return value;
}