//
// tools/ui-lint/lib/dom/stability.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function classifyMutationSeverity(stats = {}) {
    const mutationCount = Number(stats.mutationCount || 0);
    const mutationBursts = Number(stats.mutationBursts || 0);
    const reconnectCount = Number(stats.reconnectCount || 0);

    if (mutationBursts > 3 || reconnectCount > 25) return 'blocking';
    if (mutationBursts > 1 || mutationCount > 500) return 'serious';
    if (mutationCount > 50) return 'warning';
    return 'diagnostic';
}
