//
// tools/ui-lint/lib/dom-runtime/exports/verbose-schema.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { serializeVerbose } from '../runtime/serialization.mjs';

export function buildVerboseSchema(snapshot) {
    return serializeVerbose(snapshot);
}
