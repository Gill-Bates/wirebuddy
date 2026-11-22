//
// tests/layout/fixtures.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { expect, test as base } from "@playwright/test";
import { login, startApp } from "./harness.mjs";

// Worker scope: one app instance and one admin login per worker, shared by tests that do not change
// server state. The session lives in memory only; it is never written to disk or attached.
// `openContext(options, { admin })` builds a context for the test; the config-level trace and
// screenshot capture applies to it, and the fixture closes it afterwards.
export const test = base.extend({
    app: [async ({}, use) => {
        const app = await startApp("shared");
        try {
            await use(app);
        } finally {
            await app.stop();
        }
    }, { scope: "worker", timeout: 90_000 }],
    adminState: [async ({ app, browser }, use) => {
        const context = await browser.newContext();
        try {
            const page = await context.newPage();
            await login(page, app);
            // The first visit shows the onboarding modal once per browser profile. Dismiss it through the UI
            // ("don't show again") so the stored state carries the app's own flag and no test races the modal.
            const onboarding = page.locator("#wbOnboardingModal");
            await expect(onboarding).toBeVisible();
            await onboarding.locator("#wbOnboardingDismiss").check();
            await onboarding.getByRole("button", { name: "Got it!" }).click();
            await expect(onboarding).toBeHidden();
            // The app writes the flag on its hidden event, which can land after the modal looks hidden.
            await expect.poll(() => page.evaluate(() => Object.keys(localStorage).some((key) => key.startsWith("wb_onboarding_dismissed_")))).toBe(true);
            await use(await context.storageState());
        } finally {
            await context.close();
        }
    }, { scope: "worker", timeout: 90_000 }],
    openContext: async ({ browser, adminState }, use) => {
        const contexts = [];
        // admin: logged-in session; fresh: the same session without the stored onboarding flag.
        await use(async (options, { admin, fresh = false }) => {
            const storageState = !admin ? undefined : fresh ? { cookies: adminState.cookies, origins: [] } : adminState;
            const context = await browser.newContext({ ...options, ...(storageState ? { storageState } : {}) });
            contexts.push(context);
            return context;
        });
        for (const context of contexts) await context.close();
    },
});

export { expect };
