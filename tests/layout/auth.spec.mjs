//
// tests/layout/auth.spec.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Login, wrong login, logout and credential hygiene. The specs run against their own throw-away
// instance, because the login limit (5/minute) and the username lockout must never hit the session
// that the other specs share.
import fs from "node:fs";
import { expect, test } from "@playwright/test";
import { collectPageErrors, startApp } from "./harness.mjs";

test.describe.configure({ mode: "serial" });

let app;
test.beforeAll(async () => {
    app = await startApp("auth");
}, { timeout: 90_000 });
test.afterAll(async () => {
    await app?.stop();
});

test("wrong credentials keep the user on the login page with an error @layout @auth @mobile", async ({ page, browserName }) => {
    const errors = [];
    const readCsp = await collectPageErrors(page, errors, "login", app.url, browserName);
    await page.goto(`${app.url}/login`);
    await page.locator("#username").fill("no-such-user");
    await page.locator("#password").fill("not-the-password");
    await page.locator("#submit-btn").click();
    await expect(page.locator("#error-alert")).toBeVisible();
    await expect(page.locator("#error-alert")).not.toHaveClass(/is-hidden/);
    await expect(page).toHaveURL(`${app.url}/login`);
    // The rejected login itself answers 401; everything else must stay clean.
    expect((await readCsp()).filter((entry) => !/status of 401|HTTP 401/.test(entry))).toEqual([]);
});

test("login lands on the dashboard, logout returns to login and ends the session @layout @auth @mobile", async ({ page }) => {
    await page.goto(`${app.url}/login`);
    await page.locator("#username").fill(app.username);
    await page.locator("#password").fill(app.password);
    await Promise.all([
        page.waitForURL(`${app.url}/ui/dashboard`),
        page.locator("#submit-btn").click(),
    ]);
    await expect(page.locator("h1.page-title")).toBeVisible();
    // A first login shows the onboarding modal, which blocks the navbar until it is closed.
    const onboarding = page.locator("#wbOnboardingModal");
    await expect(onboarding).toBeVisible();
    await onboarding.getByRole("button", { name: "Got it!" }).click();
    await expect(onboarding).toBeHidden();

    await page.locator("#logoutBtn").click();
    await expect(page).toHaveURL(/\/login(\?.*)?$/);
    await expect(page.locator("#login-form")).toBeVisible();

    await page.goto(`${app.url}/ui/dashboard`);
    await expect(page).toHaveURL(/\/login(\?.*)?$/);
});

test("the server log never contains the generated password or secret key @layout @auth @mobile", async () => {
    const log = fs.readFileSync(app.logPath, "utf8");
    expect(log.length, "server log should not be empty").toBeGreaterThan(0);
    expect(log.includes(app.password), "admin password in server log").toBe(false);
    expect(log.includes(app.secretKey), "secret key in server log").toBe(false);
});
