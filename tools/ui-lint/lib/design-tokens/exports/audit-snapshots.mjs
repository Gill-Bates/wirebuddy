//
// tools/ui-lint/lib/design-tokens/exports/audit-snapshots.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildSerializableTokenPayload } from './serializable.mjs';

export function buildAuditTokenSnapshot(snapshot, options = {}) {
    return buildSerializableTokenPayload(snapshot, options);
}