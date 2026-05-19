//
// tools/ui-lint/lib/dom-runtime/rendering/compositing.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildCompositingSnapshot(node) {
    const style = node.style || {};
    const composited = Boolean(
        node.transformMatrix ||
        node.transforms?.transformMatrix ||
        Number.parseFloat(style.opacity || '1') < 1 ||
        /transform|opacity|filter|will-change|perspective/.test(`${style.willChange || ''} ${style.filter || ''}`)
    );

    return {
        composited,
        layerHint: composited ? 'promoted' : 'flat',
    };
}
