//
// tools/ui-lint/lib/dom-runtime/exports/snapshot-diff.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildIncrementalSnapshot } from '../runtime/incremental-snapshots.mjs';

export function diffSnapshots(current, previous = null) {
    return buildIncrementalSnapshot(current, previous);
}
