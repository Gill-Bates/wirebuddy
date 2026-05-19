//
// tools/ui-lint/lib/runtime/screenshots/screenshot-normalizer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';

export function sanitize(name) {
    return String(name || '').replace(/[^a-z0-9-_]+/g, '_').toLowerCase();
}

export function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

export function buildScreenshotPath(screenshotDir, name, suffix) {
    return `${screenshotDir}/${sanitize(name)}-${suffix}.png`;
}
