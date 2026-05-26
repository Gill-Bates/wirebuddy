//
// tools/ui-lint/lib/visual/ssim.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

import { PNG } from 'pngjs';

function toImageData(source) {
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

export async function computeSSIM(imgPathA, imgPathB) {
    try {
        const { default: ssim } = await import('ssim.js');

        const imgA = toImageData(imgPathA);
        const imgB = toImageData(imgPathB);

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

        return {
            ssim: result.ssim,
            mssim: result.mssim,
            error: null,
        };
    } catch (err) {
        return {
            ssim: null,
            mssim: null,
            error: err.message,
        };
    }
}
