//
// tools/ui-lint/lib/runtime/visual-diff/diff-classification.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function classifyDiffSeverity(ratio) {
    if (ratio >= 0.08) return 'blocking';
    if (ratio >= 0.03) return 'serious';
    if (ratio >= 0.01) return 'warning';
    return 'info';
}
