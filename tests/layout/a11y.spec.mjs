//
// tests/layout/a11y.spec.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// axe-core once per page on one canonical viewport (1280x720, light), Chromium only (the config
// leaves this file out of the other projects). Serious and critical violations fail. This is a
// smoke check; full WCAG validation needs manual testing with assistive technology.
import AxeBuilder from "@axe-core/playwright";
import { KNOWN_AXE, PAGES, contextOptions, openPage, pagesFor, VIEWPORTS } from "./harness.mjs";
import { expect, test } from "./fixtures.mjs";

const canonical = VIEWPORTS.full.find((viewport) => viewport.name === "desktop-1280x720");

for (const pageSpec of pagesFor()) {
    test(`axe finds no serious violations on ${pageSpec.id} @layout @a11y`, async ({ app, openContext }) => {
        const context = await openContext(contextOptions(canonical, "light"), { admin: pageSpec.auth === "admin" });
        const page = await context.newPage();
        await openPage(page, app, pageSpec);
        const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
        const findings = [];
        for (const violation of results.violations) {
            if (violation.impact !== "serious" && violation.impact !== "critical") continue;
            for (const node of violation.nodes) {
                const selector = node.target.join(" ");
                const known = KNOWN_AXE.find((entry) => entry.page === pageSpec.id && entry.rule === violation.id && selector.includes(entry.selector));
                if (!known) findings.push(`${violation.id} (${violation.impact}): ${selector}`);
            }
        }
        expect(findings, `axe findings on ${pageSpec.id}`).toEqual([]);
    });
}

test("known axe exceptions refer to existing pages @layout @a11y", () => {
    for (const entry of KNOWN_AXE) {
        expect(PAGES.some((page) => page.id === entry.page), `${entry.rule}: unknown page ${entry.page}`).toBe(true);
        expect(entry.reason, `${entry.rule}: reason required`).toBeTruthy();
    }
});
