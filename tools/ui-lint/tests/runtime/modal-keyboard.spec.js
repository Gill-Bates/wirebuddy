//
// tools/ui-lint/tests/runtime/modal-keyboard.spec.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test } from '@playwright/test';

import { mountContractPage, readRepoFile } from '../support/contract-fixtures.mjs';

const settingsModals = readRepoFile('app/templates/settings/_modals.html').replace(/{%[^%]*%}/g, '');

const sharedModal = `
<div class="modal fade" id="wbModal" tabindex="-1" aria-labelledby="wbModalTitle">
    <div class="modal-dialog"><div class="modal-content">
        <div class="modal-header"><h2 id="wbModalTitle"></h2><button type="button" id="wbModalClose" data-bs-dismiss="modal">Close</button></div>
        <div class="modal-body"><span id="wbModalIcon"></span><p id="wbModalMessage"></p>
            <div id="wbModalInputWrap" class="d-none"><label id="wbModalInputLabel" for="wbModalInput">Value</label><input id="wbModalInput"></div>
        </div>
        <div class="modal-footer"><button type="button" id="wbModalCancel" class="d-none" data-bs-dismiss="modal">Cancel</button><button type="button" id="wbModalOk">OK</button></div>
    </div></div>
</div>`;

async function mountModals(page) {
    await mountContractPage(page, {
        width: 1024,
        height: 768,
        stylesheetPaths: ['app/static/vendor/bootstrap.min.css'],
        body: `
            <button type="button" id="cert-trigger" data-bs-toggle="modal" data-bs-target="#certModal">Certificate</button>
            <button type="button" id="iface-trigger">Interface</button>
            <button type="button" id="confirm-trigger">Confirm action</button>
            ${settingsModals}${sharedModal}`,
    });
    await page.addScriptTag({ content: readRepoFile('app/static/vendor/bootstrap.bundle.min.js') });
    await page.addScriptTag({ content: readRepoFile('app/static/js/base-ui.js') });
    await page.evaluate(() => document.dispatchEvent(new Event('DOMContentLoaded')));
    await page.addScriptTag({ content: readRepoFile('app/static/js/modal.js') });
    await page.evaluate(() => {
        window.modalEvents = { shown: {}, hidden: {} };
        for (const type of ['shown', 'hidden']) {
            document.addEventListener(`${type}.bs.modal`, (event) => {
                const counts = window.modalEvents[type];
                counts[event.target.id] = (counts[event.target.id] || 0) + 1;
            });
        }
        window.submitCounts = { cert: 0, iface: 0 };
        document.querySelector('#cert-form').addEventListener('submit', (event) => {
            event.preventDefault();
            window.submitCounts.cert += 1;
        });
        document.querySelector('#iface-form').addEventListener('submit', (event) => {
            event.preventDefault();
            window.submitCounts.iface += 1;
        });
        document.querySelector('#iface-trigger').addEventListener('click', () => {
            bootstrap.Modal.getOrCreateInstance(document.querySelector('#ifaceModal')).show();
        });
    });
}

async function waitForModalEvent(page, type, id, count) {
    await expect.poll(() => page.evaluate(([eventType, modalId]) =>
        window.modalEvents[eventType][modalId] || 0, [type, id])).toBe(count);
}

test('form modals support Enter, Escape, and focus return for data and programmatic openings', async ({ page }) => {
    await mountModals(page);

    await page.getByRole('button', { name: 'Certificate', exact: true }).click();
    await waitForModalEvent(page, 'shown', 'certModal', 1);
    await expect(page.locator('#certModal')).toHaveAttribute('aria-modal', 'true');
    await page.locator('#cert-domain').fill('vpn.example.com');
    await page.locator('#cert-email').fill('admin@example.com');
    await page.locator('#cert-email').press('Enter');
    await expect.poll(() => page.evaluate(() => window.submitCounts.cert)).toBe(1);
    await page.locator('#cert-email').press('Escape');
    await waitForModalEvent(page, 'hidden', 'certModal', 1);
    await expect(page.locator('#cert-trigger')).toBeFocused();

    await page.locator('#cert-trigger').click();
    await waitForModalEvent(page, 'shown', 'certModal', 2);
    await page.locator('#certModal .modal-footer button[data-bs-dismiss="modal"]').focus();
    await page.keyboard.press('Enter');
    await waitForModalEvent(page, 'hidden', 'certModal', 2);
    expect(await page.evaluate(() => window.submitCounts.cert)).toBe(1);
    await expect(page.locator('#cert-trigger')).toBeFocused();

    await page.getByRole('button', { name: 'Interface', exact: true }).click();
    await waitForModalEvent(page, 'shown', 'ifaceModal', 1);
    await page.locator('#iface-name').fill('wg1');
    await page.locator('#iface-name').press('Enter');
    await expect.poll(() => page.evaluate(() => window.submitCounts.iface)).toBe(1);
    await page.locator('#iface-name').press('Escape');
    await waitForModalEvent(page, 'hidden', 'ifaceModal', 1);
    await expect(page.locator('#iface-trigger')).toBeFocused();
    await expect(page.locator('#ifaceModal .modal-footer button[data-bs-dismiss="modal"]')).toHaveAttribute('type', 'button');
});

test('Escape cancels confirm and prompt without carrying prompt text into the next dialog', async ({ page }) => {
    await mountModals(page);
    await page.locator('#confirm-trigger').focus();
    await page.evaluate(() => {
        window.confirmResult = 'pending';
        wbConfirm('Delete?').then((value) => { window.confirmResult = value; });
    });
    await waitForModalEvent(page, 'shown', 'wbModal', 1);
    await expect(page.locator('#wbModalCancel')).toBeFocused();
    await page.keyboard.press('Escape');
    await waitForModalEvent(page, 'hidden', 'wbModal', 1);
    await expect.poll(() => page.evaluate(() => window.confirmResult)).toBe(false);
    await expect(page.locator('#confirm-trigger')).toBeFocused();

    await page.evaluate(() => {
        window.confirmResult = 'pending';
        wbConfirm('Delete?').then((value) => { window.confirmResult = value; });
    });
    await waitForModalEvent(page, 'shown', 'wbModal', 2);
    await page.keyboard.press('Enter');
    await waitForModalEvent(page, 'hidden', 'wbModal', 2);
    await expect.poll(() => page.evaluate(() => window.confirmResult)).toBe(false);

    await page.evaluate(() => {
        window.promptResult = 'pending';
        wbPrompt('Enter a value', { inputType: 'password', defaultValue: 'secret' })
            .then((value) => { window.promptResult = value; });
    });
    await waitForModalEvent(page, 'shown', 'wbModal', 3);
    await expect(page.locator('#wbModalInput')).toBeFocused();
    await page.locator('#wbModalInput').fill('new secret');
    await page.keyboard.press('Escape');
    await waitForModalEvent(page, 'hidden', 'wbModal', 3);
    await expect.poll(() => page.evaluate(() => window.promptResult)).toBe(null);
    await expect(page.locator('#wbModalInput')).toHaveValue('');
    await expect(page.locator('#confirm-trigger')).toBeFocused();

    await page.evaluate(() => {
        window.promptResult = 'pending';
        wbPrompt('Enter a value').then((value) => { window.promptResult = value; });
    });
    await waitForModalEvent(page, 'shown', 'wbModal', 4);
    await page.locator('#wbModalInput').fill('  saved  ');
    await page.locator('#wbModalInput').press('Enter');
    await waitForModalEvent(page, 'hidden', 'wbModal', 4);
    await expect.poll(() => page.evaluate(() => window.promptResult)).toBe('saved');
    await expect(page.locator('#confirm-trigger')).toBeFocused();
});

test('Escape closes only the top dialog and restores focus to the form beneath it', async ({ page }) => {
    await mountModals(page);
    await page.locator('#iface-trigger').click();
    await waitForModalEvent(page, 'shown', 'ifaceModal', 1);
    await page.locator('#iface-name').focus();

    await page.evaluate(() => {
        window.nestedResult = 'pending';
        wbConfirm('Discard draft?').then((value) => { window.nestedResult = value; });
    });
    await waitForModalEvent(page, 'shown', 'wbModal', 1);
    await page.keyboard.press('Escape');
    await waitForModalEvent(page, 'hidden', 'wbModal', 1);
    await expect.poll(() => page.evaluate(() => window.nestedResult)).toBe(false);
    await expect(page.locator('#ifaceModal')).toHaveClass(/show/);
    await expect(page.locator('#iface-name')).toBeFocused();

    await page.keyboard.press('Escape');
    await waitForModalEvent(page, 'hidden', 'ifaceModal', 1);
    await expect(page.locator('#iface-trigger')).toBeFocused();
});
