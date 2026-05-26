//
// tools/ui-lint/lib/runtime/visual-diff/ssim.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { loadImageBuffer } from './pixelmatch.mjs';

export async function computeSSIM(imgPathA, imgPathB) {
    try {
        const { default: ssim } = await import('ssim.js');
        const imgA = loadImageBuffer(imgPathA);
        const imgB = loadImageBuffer(imgPathB);

        if (imgA.width !== imgB.width || imgA.height !== imgB.height) {
            return {
                ssim: null,
                mssim: null,
                error: 'dimension-mismatch',
                dimensions: {
                    a: { width: imgA.width, height: imgA.height },
                    b: { width: imgB.width, height: imgB.height },
                },
            };
        }

        const result = ssim.ssim(
            { data: imgA.data, width: imgA.width, height: imgA.height },
            { data: imgB.data, width: imgB.width, height: imgB.height }
        );

        return { ssim: result.ssim, mssim: result.mssim, error: null };
    } catch (err) {
        return { ssim: null, mssim: null, error: err.message };
    }
}
