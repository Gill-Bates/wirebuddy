//
// tests/layout/navigation.spec.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Desktop sidebar, mobile menu and the three-state theme toggle (auto -> light -> dark -> auto).
import { PAGES, collectPageErrors, contextOptions, openPage, VIEWPORTS } from "./harness.mjs";
import { expect, test } from "./fixtures.mjs";

const byName = (name) => VIEWPORTS.full.find((viewport) => viewport.name === name);
const adminPages = PAGES.filter((page) => page.auth === "admin");

test("desktop sidebar reaches every admin page and marks it active @layout @nav", async ({ app, openContext, browserName }) => {
    const context = await openContext(contextOptions(byName("desktop-1280x720"), "light"), { admin: true });
    const page = await context.newPage();
    const errors = [];
    const readCsp = await collectPageErrors(page, errors, "navigation", app.url, browserName);
    await openPage(page, app, adminPages[0]);
    const sidebar = page.getByRole("navigation", { name: "Main navigation" });
    await expect(sidebar).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Mobile navigation" })).toBeHidden();
    for (const target of adminPages) {
        await sidebar.locator(`a.nav-link[href="${target.path}"]`).click();
        await expect(page).toHaveURL(`${app.url}${target.path}`);
        await expect(page.locator(target.landmark).first()).toBeVisible();
        await expect(sidebar.locator("a.nav-link.active")).toHaveAttribute("href", target.path);
    }
    expect(await readCsp(), "runtime errors while navigating").toEqual([]);
});

test("mobile menu opens, navigates and closes with the page @layout @nav @mobile", async ({ app, openContext, browserName }) => {
    const context = await openContext(contextOptions(byName("phone-390x844"), "light"), { admin: true });
    const page = await context.newPage();
    const errors = [];
    const readCsp = await collectPageErrors(page, errors, "navigation", app.url, browserName);
    await openPage(page, app, adminPages[0]);
    await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeHidden();
    const toggler = page.getByRole("button", { name: "Toggle navigation" });
    const menu = page.locator("#navbarNav");
    await expect(toggler).toHaveAttribute("aria-expanded", "false");
    await toggler.click();
    await expect(menu).toBeVisible();
    await expect(toggler).toHaveAttribute("aria-expanded", "true");
    // The menu intercepts link clicks only once it is fully open; a tap during the open animation is
    // not handled by the app, so wait for the transition to finish before using a link.
    await expect(menu).toHaveClass(/\bshow\b/);
    await expect(menu).not.toHaveClass(/collapsing|wb-nav-opening/);
    await menu.locator('.navbar-mobile-grid a.nav-link[href="/ui/settings"]').click();
    await expect(page).toHaveURL(`${app.url}/ui/settings`);
    await expect(page.locator("h1.page-title")).toBeVisible();
    await expect(menu).toBeHidden();
    expect(await readCsp(), "runtime errors while navigating").toEqual([]);
});

test("theme toggle cycles, persists and follows the OS in auto mode @layout @nav @mobile", async ({ app, openContext, browserName }) => {
    const context = await openContext(contextOptions(byName("phone-390x844"), "dark"), { admin: true });
    const page = await context.newPage();
    const html = page.locator("html");
    await openPage(page, app, adminPages[0], "dark");
    // Auto follows the emulated OS scheme (dark here).
    await expect(html).toHaveAttribute("data-wb-theme-mode", "auto");
    await expect(html).toHaveAttribute("data-bs-theme", "dark");
    const toggle = page.locator("#themeToggle");
    await toggle.click();
    await expect(html).toHaveAttribute("data-wb-theme-mode", "light");
    await expect(html).toHaveAttribute("data-bs-theme", "light");
    await toggle.click();
    await expect(html).toHaveAttribute("data-wb-theme-mode", "dark");
    await page.reload({ waitUntil: "load" });
    await expect(html).toHaveAttribute("data-wb-theme-mode", "dark");
    await expect(html).toHaveAttribute("data-bs-theme", "dark");
    await page.locator("#themeToggle").click();
    await expect(html).toHaveAttribute("data-wb-theme-mode", "auto");
    await page.emulateMedia({ colorScheme: "light" });
    await expect(html).toHaveAttribute("data-bs-theme", "light");
});
