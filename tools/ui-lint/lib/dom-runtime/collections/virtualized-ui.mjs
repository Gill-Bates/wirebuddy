//
// tools/ui-lint/lib/dom-runtime/collections/virtualized-ui.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function detectVirtualizedUi(node) {
    const estimatedItemCount = Number.parseInt(node.attributes?.['aria-setsize'] || node.attributes?.['data-estimated-item-count'] || '', 10) || null;
    return {
        virtualized: Boolean(
            node.attributes?.['data-virtualized'] === 'true' ||
            node.attributes?.role === 'listbox' && estimatedItemCount !== null
        ),
        estimatedItemCount,
    };
}
