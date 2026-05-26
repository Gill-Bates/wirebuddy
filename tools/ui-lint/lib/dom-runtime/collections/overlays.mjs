//
// tools/ui-lint/lib/dom-runtime/collections/overlays.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildOverlaySnapshot(nodes) {
    return nodes.filter((node) => node.positioning?.fixed || node.positioning?.sticky || node.accessibility?.computedRole === 'dialog');
}
