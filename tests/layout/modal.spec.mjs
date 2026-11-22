//
// tests/layout/modal.spec.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Add-user modal on /ui/users: opens with focus inside, closes by button and Escape, leaves the page
// scrollable and the layout unchanged. Nothing is submitted, so no user is created.
import { PAGES, auditPage, collectPageErrors, contextOptions, openPage, VIEWPORTS } from "./harness.mjs";
import { expect, test } from "./fixtures.mjs";

const usersPage = PAGES.find((page) => page.id === "users");

for (const name of ["desktop-1280x720", "phone-390x844"]) {
    const viewport = VIEWPORTS.full.find((entry) => entry.name === name);
    test(`add-user modal opens and closes at ${name} @layout @modal ${viewport.mobile ? "@mobile" : ""}`, async ({ app, openContext, browserName }) => {
        const context = await openContext(contextOptions(viewport, "light"), { admin: true });
        const page = await context.newPage();
        const errors = [];
        const readCsp = await collectPageErrors(page, errors, "users", app.url, browserName);
        await openPage(page, app, usersPage);
        const modal = page.locator("#addUserModal");
        const opener = page.locator('[data-bs-target="#addUserModal"]').first();
        const body = page.locator("body");

        await opener.click();
        await expect(modal).toBeVisible();
        await expect(modal).toHaveClass(/show/);
        await expect.poll(() => modal.evaluate((element) => element.contains(document.activeElement))).toBe(true);
        await expect(body).toHaveClass(/modal-open/);
        expect(await auditPage(page), "overflow with the modal open").toEqual([]);

        await modal.locator(".btn-close").click();
        await expect(modal).toBeHidden();
        await expect(body).not.toHaveClass(/modal-open/);
        await expect.poll(() => body.evaluate((element) => element.style.overflow)).not.toBe("hidden");

        await opener.click();
        await expect(modal).toBeVisible();
        // Bootstrap ignores Escape while the show transition runs; focus moving inside marks it finished.
        await expect.poll(() => modal.evaluate((element) => element.contains(document.activeElement))).toBe(true);
        await page.keyboard.press("Escape");
        await expect(modal).toBeHidden();
        await expect(body).not.toHaveClass(/modal-open/);
        expect(await auditPage(page), "overflow after closing").toEqual([]);
        expect(await readCsp(), "runtime errors").toEqual([]);
    });
}

test("first-visit onboarding modal appears and is dismissed for good @layout @modal @mobile", async ({ app, openContext, browserName }) => {
    const context = await openContext(contextOptions(VIEWPORTS.full.find((entry) => entry.name === "phone-390x844"), "light"), { admin: true, fresh: true });
    const page = await context.newPage();
    const errors = [];
    const readCsp = await collectPageErrors(page, errors, "dashboard", app.url, browserName);
    await openPage(page, app, PAGES.find((entry) => entry.id === "dashboard"));
    const modal = page.locator("#wbOnboardingModal");
    await expect(modal).toBeVisible();
    expect(await auditPage(page), "overflow with the onboarding modal open").toEqual([]);
    await modal.locator("#wbOnboardingDismiss").check();
    await modal.getByRole("button", { name: "Got it!" }).click();
    await expect(modal).toBeHidden();
    await expect.poll(() => page.evaluate(() => Object.keys(localStorage).some((key) => key.startsWith("wb_onboarding_dismissed_")))).toBe(true);
    expect(await readCsp(), "runtime errors").toEqual([]);
});
