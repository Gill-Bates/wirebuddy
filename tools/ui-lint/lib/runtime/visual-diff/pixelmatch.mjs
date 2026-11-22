//
// tools/ui-lint/lib/runtime/visual-diff/pixelmatch.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

import { loadDep } from '../../deps.mjs';

const { default: pixelmatch } = await loadDep('pixelmatch');
const { PNG } = await loadDep('pngjs');

export function loadImageBuffer(source) {
    if (typeof source === 'string') {
        return PNG.sync.read(fs.readFileSync(source));
    }

    if (source instanceof Uint8Array || Buffer.isBuffer(source)) {
        return PNG.sync.read(Buffer.from(source));
    }

    if (source?.data && source?.width && source?.height) {
        return source;
    }

    throw new Error('Unsupported image input');
}

export function normalizeDimensions(imageA, imageB) {
    if (imageA.width !== imageB.width || imageA.height !== imageB.height) {
        return {
            width: Math.min(imageA.width, imageB.width),
            height: Math.min(imageA.height, imageB.height),
            sizeMismatch: true,
        };
    }

    return {
        width: imageA.width,
        height: imageA.height,
        sizeMismatch: false,
    };
}

export function computePixelDiff(imageA, imageB, { threshold = 0.1 } = {}) {
    const dimensions = normalizeDimensions(imageA, imageB);
    const pngA = new PNG({ width: dimensions.width, height: dimensions.height });
    const pngB = new PNG({ width: dimensions.width, height: dimensions.height });

    PNG.bitblt(imageA, pngA, 0, 0, dimensions.width, dimensions.height, 0, 0);
    PNG.bitblt(imageB, pngB, 0, 0, dimensions.width, dimensions.height, 0, 0);

    const diff = new PNG({ width: dimensions.width, height: dimensions.height });
    const mismatchedPixels = pixelmatch(pngA.data, pngB.data, diff.data, dimensions.width, dimensions.height, { threshold });

    // Area outside the shared crop exists in one image only and counts as fully
    // different, so a taller page cannot report a zero ratio.
    const unionPixels = Math.max(imageA.width, imageB.width) * Math.max(imageA.height, imageB.height);
    const overlapPixels = dimensions.width * dimensions.height;
    const nonOverlapPixels = unionPixels - overlapPixels;

    return {
        diff,
        mismatchedPixels: mismatchedPixels + nonOverlapPixels,
        totalPixels: unionPixels,
        nonOverlapPixels,
        dimensions,
    };
}
