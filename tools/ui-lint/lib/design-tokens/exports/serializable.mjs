//
// tools/ui-lint/lib/design-tokens/exports/serializable.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildSerializableTokenPayload(snapshot, { category } = {}) {
    if (!category) {
        return structuredClone(snapshot.values || snapshot);
    }

    return structuredClone(snapshot.categories?.[category] || snapshot.values?.[category] || {});
}