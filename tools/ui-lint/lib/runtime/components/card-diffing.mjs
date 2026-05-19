//
// tools/ui-lint/lib/runtime/components/card-diffing.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

import { PNG } from 'pngjs';
import pixelmatch from 'pixelmatch';

export function diffKpiSets(nameA, setA, nameB, setB) {
    const results = [];
    const minSetLength = Math.min(setA.length, setB.length);

    for (let i = 0; i < minSetLength; i += 1) {
        const img1 = PNG.sync.read(fs.readFileSync(setA[i]));
        const img2 = PNG.sync.read(fs.readFileSync(setB[i]));

        const width = Math.min(img1.width, img2.width);
        const height = Math.min(img1.height, img2.height);
        const pngA = new PNG({ width, height });
        const pngB = new PNG({ width, height });

        PNG.bitblt(img1, pngA, 0, 0, width, height, 0, 0);
        PNG.bitblt(img2, pngB, 0, 0, width, height, 0, 0);

        const diff = new PNG({ width, height });
        const mismatched = pixelmatch(pngA.data, pngB.data, diff.data, width, height, { threshold: 0.1 });

        results.push({ index: i, ratio: mismatched / (width * height) });
    }

    return results;
}
