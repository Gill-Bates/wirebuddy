//
// tools/ui-lint/lib/dom-runtime/geometry/transforms.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function parseMatrix(transformValue) {
    if (!transformValue || transformValue === 'none') {
        return [1, 0, 0, 1, 0, 0];
    }

    const matrixMatch = /matrix\(([^)]+)\)/.exec(transformValue);
    if (matrixMatch) {
        return matrixMatch[1].split(',').map((part) => Number.parseFloat(part.trim()) || 0).slice(0, 6);
    }

    const matrix3dMatch = /matrix3d\(([^)]+)\)/.exec(transformValue);
    if (matrix3dMatch) {
        const values = matrix3dMatch[1].split(',').map((part) => Number.parseFloat(part.trim()) || 0);
        return [values[0], values[1], values[4], values[5], values[12] || 0, values[13] || 0];
    }

    return [1, 0, 0, 1, 0, 0];
}

export function parseTransforms(style) {
    return {
        transformMatrix: parseMatrix(style.transform),
        transformOrigin: style.transformOrigin || '50% 50%',
    };
}

export function normalizeGeometry(rect, scale = 1) {
    const round = (value) => Math.round(value * scale * 10) / 10;
    return {
        left: round(rect.left || 0),
        top: round(rect.top || 0),
        right: round(rect.right || ((rect.left || 0) + (rect.width || 0))),
        bottom: round(rect.bottom || ((rect.top || 0) + (rect.height || 0))),
        width: round(rect.width || 0),
        height: round(rect.height || 0),
    };
}
