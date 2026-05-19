//
// tools/ui-lint/lib/dom-runtime/geometry/coordinate-spaces.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildCoordinateSpaces(node, viewport) {
    const rect = node.rect || { left: 0, top: 0, width: 0, height: 0 };
    const scrollX = viewport?.scrollX || 0;
    const scrollY = viewport?.scrollY || 0;
    const transform = node.transformMatrix || [1, 0, 0, 1, 0, 0];

    return {
        viewport: rect,
        document: {
            left: rect.left + scrollX,
            top: rect.top + scrollY,
            width: rect.width,
            height: rect.height,
        },
        transformed: {
            left: rect.left,
            top: rect.top,
            width: rect.width,
            height: rect.height,
            matrix: transform,
        },
        visualViewport: {
            left: rect.left * (viewport?.scale || 1),
            top: rect.top * (viewport?.scale || 1),
            width: rect.width * (viewport?.scale || 1),
            height: rect.height * (viewport?.scale || 1),
        },
    };
}
