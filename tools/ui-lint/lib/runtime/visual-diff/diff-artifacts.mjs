//
// tools/ui-lint/lib/runtime/visual-diff/diff-artifacts.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

import { PNG } from 'pngjs';

import { sanitize } from '../screenshots/screenshot-normalizer.mjs';
import { computePixelDiff, loadImageBuffer } from './pixelmatch.mjs';

export function writeDiffArtifact({ name, diff, screenshotDir }) {
    const diffPath = `${screenshotDir}/${sanitize(name)}-diff.png`;
    fs.writeFileSync(diffPath, PNG.sync.write(diff));
    return diffPath;
}

export function diffScreenshots({ name, shotA, shotB, screenshotDir, threshold = 0.1 }) {
    const img1 = loadImageBuffer(shotA);
    const img2 = loadImageBuffer(shotB);
    const { diff, mismatchedPixels, totalPixels, dimensions } = computePixelDiff(img1, img2, { threshold });
    const diffPath = writeDiffArtifact({ name, diff, screenshotDir });

    return {
        mismatchedPixels,
        totalPixels,
        ratio: totalPixels > 0 ? mismatchedPixels / totalPixels : 0,
        sizeMismatch: dimensions.sizeMismatch,
        dimensions: dimensions.sizeMismatch ? { img1: { width: img1.width, height: img1.height }, img2: { width: img2.width, height: img2.height } } : null,
        diffPath,
    };
}
