//
// tools/ui-lint/lib/design-tokens/exports/browser-payloads.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildSerializableTokenPayload } from './serializable.mjs';

export function buildBrowserTokenPayload(snapshot, options = {}) {
    return buildSerializableTokenPayload(snapshot, options);
}