//
// tools/ui-lint/lib/runtime/visual-diff/pixelmatch.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

import pixelmatch from 'pixelmatch';
import { PNG } from 'pngjs';

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

    return { diff, mismatchedPixels, totalPixels: dimensions.width * dimensions.height, dimensions };
}
