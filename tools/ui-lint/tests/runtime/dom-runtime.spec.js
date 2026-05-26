//
// tools/ui-lint/tests/runtime/dom-runtime.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import path from 'node:path';

import { expect, test } from '@playwright/test';

const domScriptPath = path.resolve('/opt/wirebuddy/app/static/js/core/dom.js');

test.beforeEach(async ({ page }) => {
    await page.setContent('<!doctype html><html><body></body></html>');
    await page.addScriptTag({ path: domScriptPath });
});

test('legacy element helper stays XSS-safe and still returns live nodes', async ({ page }) => {
    const result = await page.evaluate(() => {
        const badge = window.el('span', {
            class: 'badge bg-success',
            text: '<unsafe>',
            data: { state: 'ok' },
        });

        const container = document.createElement('div');
        window.WBDom.replaceContent(container, [badge]);

        return {
            html: container.innerHTML,
            text: badge.textContent,
            className: badge.className,
            dataState: badge.dataset.state,
        };
    });

    expect(result.text).toBe('<unsafe>');
    expect(result.className).toBe('badge bg-success');
    expect(result.dataState).toBe('ok');
    expect(result.html).toContain('&lt;unsafe&gt;');
});

test('render queues DOM commits and batches reactive updates deterministically', async ({ page }) => {
    const result = await page.evaluate(async () => {
        const { createSignal, effect, h, render, yieldToMainThread } = window.WBDom;
        const container = document.createElement('section');
        document.body.appendChild(container);

        const [count, setCount] = createSignal(0);
        const observed = [];

        effect(() => {
            observed.push(count());
            void render(h('div', {
                id: 'counter-root',
                children: [h('span', { text: `Count: ${count()}` })],
            }), container);
        });

        setCount(1);
        setCount(2);
        await yieldToMainThread();

        return {
            text: container.querySelector('#counter-root')?.textContent,
            observed,
            snapshot: window.WBDom.getRuntimeSnapshot(),
        };
    });

    expect(result.text).toBe('Count: 2');
    expect(result.observed).toEqual([0, 2]);
    expect(result.snapshot.metrics.commitCount).toBeGreaterThan(0);
    expect(result.snapshot.metrics.renderDuration).toBeGreaterThanOrEqual(0);
});

test('context providers and renderToString work through the runtime layer', async ({ page }) => {
    const result = await page.evaluate(async () => {
        const { createContext, createPortal, h, render, renderToString, useContext } = window.WBDom;
        const container = document.createElement('div');
        const portalTarget = document.createElement('div');
        document.body.appendChild(container);
        document.body.appendChild(portalTarget);

        const Theme = createContext('light');

        function Label() {
            return h('span', { text: useContext(Theme) });
        }

        await render(h(Theme.Provider, {
            value: 'dark',
            children: [
                h('div', {
                    id: 'theme-root',
                    children: [h(Label)],
                }),
                createPortal([h('strong', { text: 'portal' })], portalTarget),
            ],
        }), container);

        const html = renderToString(h('div', {
            class: 'runtime-card',
            attrs: { role: 'presentation' },
            children: [h('span', { text: 'safe' })],
        }));

        return {
            themeText: container.querySelector('#theme-root')?.textContent,
            portalText: portalTarget.textContent,
            html,
        };
    });

    expect(result.themeText).toBe('dark');
    expect(result.portalText).toBe('portal');
    expect(result.html).toContain('runtime-card');
    expect(result.html).toContain('safe');
});

test('settings action buttons bind through delegated runtime events', async ({ page }) => {
    await page.addScriptTag({ path: path.resolve('/opt/wirebuddy/app/static/js/settings/components.js') });

    const result = await page.evaluate(() => {
        let clicked = 0;
        const button = window.WB.settingsComponents.actionButton({
            icon: 'play_arrow',
            variant: 'success',
            title: 'Start',
            onClick: () => { clicked += 1; },
        });

        document.body.appendChild(button);
        button.click();

        return {
            clicked,
            className: button.className,
            ariaLabel: button.getAttribute('aria-label'),
        };
    });

    expect(result.clicked).toBe(1);
    expect(result.className).toContain('btn-outline-success');
    expect(result.ariaLabel).toBe('Start');
});

test('settings components sanitize datasets and boolean attributes deterministically', async ({ page }) => {
    await page.addScriptTag({ path: path.resolve('/opt/wirebuddy/app/static/js/settings/components.js') });

    const result = await page.evaluate(() => {
        const { actionButton, blocklistItem, certificateRow } = window.WB.settingsComponents;

        const button = actionButton({
            icon: 'delete',
            variant: 'danger',
            title: 'Delete',
            disabled: false,
            data: {
                safe: 'ok',
                __proto__: 'polluted',
                constructor: 'polluted',
            },
        });

        const blocklist = blocklistItem({
            enabled: false,
            name: 'Blocklist A',
            url: 'https://example.org/blocklist.json',
            description: 'Example blocklist',
            domains: 0,
            last_updated: '2026-05-19',
        }, 0, {
            rebuildInProgress: false,
            isAdmin: false,
            dnsUnavailable: false,
        });

        const certificate = certificateRow({
            domain: 'example.org',
            expires_at: '2026-05-20T00:00:00Z',
            days_until_expiry: 7,
            needs_renewal: false,
            is_staging: false,
            issuer: 'ACME',
        });

        return {
            buttonDisabled: button.hasAttribute('disabled'),
            buttonDatasetKeys: Object.keys(button.dataset),
            iconHidden: button.querySelector('[aria-hidden="true"]') !== null,
            blocklistCheckboxDisabled: blocklist.querySelector('input')?.hasAttribute('disabled') || false,
            blocklistCheckboxChecked: blocklist.querySelector('input')?.hasAttribute('checked') || false,
            certificateText: certificate.querySelector('small')?.textContent || '',
        };
    });

    expect(result.buttonDisabled).toBe(false);
    expect(result.buttonDatasetKeys).toEqual(['safe']);
    expect(result.iconHidden).toBe(true);
    expect(result.blocklistCheckboxDisabled).toBe(true);
    expect(result.blocklistCheckboxChecked).toBe(false);
    expect(result.certificateText).toContain('20 May 2026');
});