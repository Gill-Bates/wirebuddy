//
// tools/ui-lint/tests/runtime/dom-snapshot.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import {
    collectDOMSnapshot,
    diffSnapshots,
    getByClass,
    getByDataUi,
    getByTag,
} from '../../lib/dom-snapshot.mjs';

test('dom snapshot engine captures deterministic rendering state and shadow DOM content', async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await page.setContent(`
        <!doctype html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <style>
                    body {
                        margin: 0;
                        font-family: sans-serif;
                    }
                    main.main-content {
                        padding: 24px;
                    }
                    .card {
                        border: 1px solid #d1d5db;
                        padding: 16px;
                        margin-bottom: 16px;
                    }
                    .btn {
                        display: inline-flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .badge {
                        display: inline-block;
                        margin-left: 8px;
                    }
                </style>
                <script>
                    customElements.define('ui-shadow-card', class extends HTMLElement {
                        connectedCallback() {
                            if (this.shadowRoot) {
                                return;
                            }

                            const root = this.attachShadow({ mode: 'open' });
                            root.innerHTML = '<button class="btn" data-ui="shadow-action" aria-label="Shadow action">Shadow Action</button><span class="badge">Shadow badge</span>';
                        }
                    });
                </script>
            </head>
            <body>
                <main class="main-content">
                    <section class="card" data-ui="card" aria-label="Primary card">
                        <button class="btn" data-ui="primary-action">Primary Action</button>
                        <span class="badge">Hot</span>
                    </section>
                    <ui-shadow-card></ui-shadow-card>
                    <div class="card" data-ui="scroll-shell" style="overflow: auto; max-height: 120px;">
                        <div style="height: 240px; width: 100%;">Scrollable content</div>
                    </div>
                </main>
            </body>
        </html>
    `);

    const snapshot = await collectDOMSnapshot(page, { maxNodes: 200 });
    const repeat = await collectDOMSnapshot(page, { maxNodes: 200 });

    expect(snapshot.engine).toBe('dom-runtime');
    expect(snapshot.viewport.width).toBe(1024);
    expect(snapshot.visualViewport.scale).toBe(1);
    expect(snapshot.nodeCount).toBe(snapshot.nodes.length);
    expect(snapshot.nodes.every((node) => typeof node.stableId === 'string' && node.stableId.length > 0)).toBe(true);
    expect(snapshot.nodes.map((node) => node.stableId)).toEqual(repeat.nodes.map((node) => node.stableId));
    expect(diffSnapshots(snapshot, repeat)).toEqual({ added: [], removed: [], changed: [] });

    expect(getByDataUi(snapshot, 'shadow-action')).toHaveLength(1);
    expect(getByDataUi(snapshot, 'primary-action')).toHaveLength(1);
    expect(getByClass(snapshot, 'badge').length).toBeGreaterThanOrEqual(2);
    expect(getByTag(snapshot, 'BUTTON').length).toBeGreaterThanOrEqual(2);
    expect(snapshot.collections.interactive.length).toBeGreaterThanOrEqual(2);
    expect(snapshot.collections.scrollContainers).toHaveLength(1);
    expect(snapshot.semanticGroups.navigation).toBeDefined();
    expect(snapshot.layout.nodes.length).toBe(snapshot.nodeCount);
    expect(snapshot.rendering.paintOrder.length).toBe(snapshot.nodeCount);
    expect(diffSnapshots(snapshot, snapshot)).toEqual({ added: [], removed: [], changed: [] });
});
