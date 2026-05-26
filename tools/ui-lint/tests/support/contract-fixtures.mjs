//
// tools/ui-lint/tests/support/contract-fixtures.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');

const baseStyles = `
:root {
    --bs-body-bg: #ffffff;
    --bs-body-color: #111827;
    --bs-border-color: #d1d5db;
    --bs-border-color-translucent: rgba(209, 213, 219, 0.6);
    --bs-secondary-color: #6b7280;
    --bs-secondary-bg: #e5e7eb;
    --bs-tertiary-bg: #f3f4f6;
    --bs-font-monospace: var(--wb-font-mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace);
    --wb-primary: #88171a;
    --wb-space-1: 6px;
    --wb-space-2: 12px;
    --wb-space-3: 24px;
    --wb-space-4: 32px;
}

*,
*::before,
*::after {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    padding: 0;
    width: 100%;
}

body {
    overflow-x: hidden;
    font-family: var(--wb-font-sans, system-ui, sans-serif);
}

main.main-content {
    width: 100%;
}

button {
    font: inherit;
}

.material-icons {
    font-size: 18px;
    line-height: 1;
}
`;

function stripCssImports(css) {
    return css.replace(/^\s*@import[^;]+;\s*/gm, '');
}

/**
 * Read a repository file relative to the repository root.
 * @param {string} relativePath
 * @returns {string}
 */
export function readRepoFile(relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

/**
 * Build a style sheet bundle for synthetic contract pages.
 * @param {...string} stylesheetPaths
 * @returns {string}
 */
export function buildContractStyles(...stylesheetPaths) {
    return [baseStyles, ...stylesheetPaths.map((relativePath) => stripCssImports(readRepoFile(relativePath)))].join('\n');
}

/**
 * Mount a synthetic contract page at a specific viewport size.
 * @param {import('@playwright/test').Page} page
 * @param {Object} options
 * @param {number} [options.width=390]
 * @param {number} [options.height=844]
 * @param {string[]} [options.stylesheetPaths=[]]
 * @param {string} [options.body='']
 */
export async function mountContractPage(page, { width = 390, height = 844, stylesheetPaths = [], body = '' } = {}) {
    await page.setViewportSize({ width, height });
    await page.setContent(`<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>${buildContractStyles(...stylesheetPaths)}</style>
</head>
<body>
    <main class="main-content">${body}</main>
</body>
</html>`);
}