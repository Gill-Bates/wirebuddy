//
// tools/ui-lint/lib/deps.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// The one place that decides where a third-party package is loaded from: the shared toolset in
// PLAYWRIGHT_DIR (e.g. /opt/ux-test-tools) when it ships the package, this project's own
// node_modules otherwise. The fallback is per package, so a shared dir that only carries
// playwright and axe still works for postcss, pixelmatch, pngjs and ssim.js.
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const sharedDir = process.env.PLAYWRIGHT_DIR ? path.resolve(process.env.PLAYWRIGHT_DIR) : '';
const sharedRequire = sharedDir ? createRequire(path.join(sharedDir, 'noop.js')) : null;

// Resolution misses (not installed, or ESM-only without a "require" export) fall back to the local
// copy; a package that is found but fails to load is a real error and propagates.
export async function loadDep(name) {
    if (sharedRequire) {
        let file = null;
        try {
            file = sharedRequire.resolve(name);
        } catch (error) {
            if (error?.code !== 'MODULE_NOT_FOUND' && error?.code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw error;
        }
        if (file) return import(pathToFileURL(file).href);
    }
    return import(name);
}
