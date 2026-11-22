//
// tests/layout/layout.spec.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// One smoke test per page x viewport x theme: renders, no horizontal overflow, no page, console or
// CSP errors, no 429/5xx. The matrix comes from the profile (see harness.mjs).
import { auditPage, auditSelfTest, collectPageErrors, contextOptions, layoutProfile, openPage, pagesFor, themesFor, viewportsFor } from "./harness.mjs";
import { expect, test } from "./fixtures.mjs";

const profile = layoutProfile();

// Not tagged @layout: the PR gate runs it as its own mandatory step (`run.mjs --self-test`).
test("layout audit detects injected defects @audit-self-test @mobile", async ({ page }) => {
    const { defect, control } = await auditSelfTest(page);
    expect(defect.length, "the audit must flag an element wider than the viewport").toBeGreaterThan(0);
    expect(control, "the audit must stay silent on a clean page").toEqual([]);
});

for (const viewport of viewportsFor(profile)) {
    for (const theme of themesFor(profile, viewport)) {
        for (const pageSpec of pagesFor()) {
            const tags = ["@layout", ...(viewport.mobile ? ["@mobile"] : []), ...(viewport.deviceEmulation ? ["@device"] : [])];
            test(`${pageSpec.id} at ${viewport.name} [${theme}] ${tags.join(" ")}`, async ({ app, openContext, browserName }) => {
                const context = await openContext(contextOptions(viewport, theme), { admin: pageSpec.auth === "admin" });
                const page = await context.newPage();
                const errors = [];
                const readCsp = await collectPageErrors(page, errors, pageSpec.id, app.url, browserName);
                await openPage(page, app, pageSpec, theme);
                await expect(page.locator("html")).toHaveAttribute("data-bs-theme", theme);
                expect(await auditPage(page), `${pageSpec.id} overflow`).toEqual([]);
                expect(await readCsp(), `${pageSpec.id} runtime errors`).toEqual([]);
            });
        }
    }
}
