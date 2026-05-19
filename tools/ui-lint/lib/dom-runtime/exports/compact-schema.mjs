//
// tools/ui-lint/lib/dom-runtime/exports/compact-schema.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { serializeCompact } from '../runtime/serialization.mjs';

export function buildCompactSchema(snapshot) {
    return serializeCompact(snapshot);
}
