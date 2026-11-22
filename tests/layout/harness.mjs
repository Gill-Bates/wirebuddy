//
// tests/layout/harness.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Shared pieces of the Playwright layout suite: the isolated app instance, the page catalogue,
// the viewport/theme matrix per profile, the overflow audit and the page-error collector.
// Every instance runs the real app through tests/e2e/run_server.py with a throwaway data
// directory and random credentials that only travel through the child's environment.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { devices, expect } from "@playwright/test";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const PROFILES = ["quick", "full"];

// ---------------------------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------------------------

export function layoutProfile() {
    const raw = process.env.WIREBUDDY_LAYOUT_PROFILE || "quick";
    if (!PROFILES.includes(raw)) throw new Error(`WIREBUDDY_LAYOUT_PROFILE must be one of ${PROFILES.join(", ")}, got ${JSON.stringify(raw)}`);
    return raw;
}

// Comma separated page ids; an unknown id is an error, so a typo cannot silently select nothing.
export function selectedPageIds() {
    const raw = process.env.WIREBUDDY_LAYOUT_PAGES;
    if (!raw) return null;
    const ids = raw.split(",").map((id) => id.trim()).filter(Boolean);
    const unknown = ids.filter((id) => !PAGES.some((page) => page.id === id));
    if (!ids.length || unknown.length) throw new Error(`WIREBUDDY_LAYOUT_PAGES: unknown page id(s) ${unknown.join(", ") || "(empty)"}; known: ${PAGES.map((page) => page.id).join(", ")}`);
    return new Set(ids);
}

export function selectedViewportNames() {
    const raw = process.env.WIREBUDDY_LAYOUT_VIEWPORTS;
    if (!raw) return null;
    const names = raw.split(",").map((name) => name.trim()).filter(Boolean);
    const known = new Set(VIEWPORTS.full.map((viewport) => viewport.name));
    const unknown = names.filter((name) => !known.has(name));
    if (!names.length || unknown.length) throw new Error(`WIREBUDDY_LAYOUT_VIEWPORTS: unknown viewport(s) ${unknown.join(", ") || "(empty)"}; known: ${[...known].join(", ")}`);
    return new Set(names);
}

function logDir() {
    const dir = process.env.WIREBUDDY_LAYOUT_LOGS || path.join(os.tmpdir(), `wirebuddy-layout-logs-${process.ppid}`);
    fs.mkdirSync(dir, { recursive: true });
    return dir;
}

// ---------------------------------------------------------------------------------------------
// Isolated app instance
// ---------------------------------------------------------------------------------------------

const children = new Set();
const killChildren = () => {
    for (const child of children) if (child.exitCode === null) child.kill("SIGKILL");
};
process.once("exit", killChildren);

function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

let instanceCounter = 0;

// Starts the app on a free port with a freshly seeded admin and returns { url, username, password,
// secretKey, logPath, stop }. The python interpreter comes from WIREBUDDY_LAYOUT_PYTHON and defaults to
// <repo>/.venv/bin/python; the launcher is resolved from this file's own repository root.
export async function startApp(label = "app") {
    const port = await freePort();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "wirebuddy-layout-data-"));
    const username = "layout-admin";
    const password = `Lay1!${crypto.randomBytes(15).toString("base64url")}`;
    const secretKey = crypto.randomBytes(32).toString("base64");
    const python = process.env.WIREBUDDY_LAYOUT_PYTHON || path.join(ROOT, ".venv/bin/python");
    const logPath = path.join(logDir(), `server-${label}-${process.pid}-${(instanceCounter += 1)}.log`);
    const logFd = fs.openSync(logPath, "a");
    const child = spawn(python, [path.join(ROOT, "tests/e2e/run_server.py"), dataDir, String(port)], {
        cwd: ROOT,
        env: {
            ...process.env,
            PYTHONUNBUFFERED: "1",
            NO_COLOR: "1",
            E2E_ADMIN_USERNAME: username,
            E2E_ADMIN_PASSWORD: password,
            WIREBUDDY_SECRET_KEY: secretKey,
        },
        stdio: ["ignore", logFd, logFd],
    });
    fs.closeSync(logFd);
    children.add(child);
    let spawnError = null;
    child.once("error", (error) => { spawnError = error; });
    const url = `http://127.0.0.1:${port}`;
    const stop = async () => {
        try {
            if (child.exitCode === null && child.signalCode === null) {
                const exited = new Promise((resolve) => child.once("exit", resolve));
                child.kill("SIGTERM");
                const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
                await exited;
                clearTimeout(timer);
            }
        } finally {
            children.delete(child);
            fs.rmSync(dataDir, { recursive: true, force: true });
        }
    };
    try {
        const deadline = Date.now() + 60_000;
        let up = false;
        while (!up) {
            if (spawnError) throw new Error(`cannot start ${python}: ${spawnError.message}`);
            if (child.exitCode !== null || child.signalCode !== null) throw new Error(`app exited during start (code ${child.exitCode}); see ${logPath}`);
            if (Date.now() > deadline) throw new Error(`app did not answer /login within 60 s; see ${logPath}`);
            try {
                up = (await fetch(`${url}/login`)).ok;
            } catch {
                // not listening yet
            }
            if (!up) await new Promise((resolve) => setTimeout(resolve, 200));
        }
        // An armed first-boot gate would redirect every view; fail with the reason instead.
        const status = await (await fetch(`${url}/api/system/status`)).text();
        if (status.includes("bootstrap_waiting")) throw new Error("bootstrap gate is active; the admin seed did not take effect");
    } catch (error) {
        await stop();
        throw error;
    }
    return { url, username, password, secretKey, logPath, stop };
}

// Logs in through the form like a user; resolves once the page left /login.
export async function login(page, app) {
    await page.goto(`${app.url}/login`);
    await page.locator("#username").fill(app.username);
    await page.locator("#password").fill(app.password);
    await Promise.all([
        page.waitForURL((url) => !url.pathname.startsWith("/login")),
        page.locator("#submit-btn").click(),
    ]);
}

// ---------------------------------------------------------------------------------------------
// Pages, viewports, themes
// ---------------------------------------------------------------------------------------------

// auth: "admin" needs the logged-in session, "anonymous" must be opened without one.
// status: the status page is disabled by default and answers 404 with its own page; it is never
// enabled here because enabling it makes the app probe the outbound network.
export const PAGES = [
    { id: "login", path: "/login", auth: "anonymous", status: 200, landmark: "#login-form" },
    { id: "dashboard", path: "/ui/dashboard", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "traffic", path: "/ui/traffic", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "dns", path: "/ui/dns", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "peers", path: "/ui/peers", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "users", path: "/ui/users", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "nodes", path: "/ui/nodes", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "settings", path: "/ui/settings", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "about", path: "/ui/about", auth: "admin", status: 200, landmark: "h1.page-title" },
    { id: "status", path: "/status", auth: "anonymous", status: 404, landmark: "h1" },
];

// mobile: the test carries @mobile and therefore also runs in the WebKit project.
// device: a Playwright device descriptor (touch, mobile user agent); Firefox cannot emulate it.
const phone = (name, width, height) => ({ name, width, height, mobile: true });
const tablet = (name, width, height) => ({ name, width, height, mobile: true });
const desktop = (name, width, height) => ({ name, width, height, mobile: false });
const device = (name, descriptor) => ({ name, device: descriptor, mobile: true, deviceEmulation: true });

const quickViewports = [
    desktop("desktop-1280x720", 1280, 720),
    desktop("laptop-1024x768", 1024, 768),
    tablet("tablet-768x1024", 768, 1024),
    phone("phone-390x844", 390, 844),
    phone("phone-320x640", 320, 640),
    device("iphone-14", "iPhone 14"),
];

export const VIEWPORTS = {
    quick: quickViewports,
    // Adds the Bootstrap breakpoints (lg = 992 px, sm = 576 px) and one pixel on each side, large
    // desktops and the iPad Pro in both orientations.
    full: [
        ...quickViewports,
        desktop("desktop-1920x1080", 1920, 1080),
        desktop("laptop-1366x768", 1366, 768),
        desktop("breakpoint-lg-992x700", 992, 700),
        tablet("breakpoint-below-lg-991x700", 991, 700),
        phone("breakpoint-sm-576x800", 576, 800),
        phone("breakpoint-below-sm-575x800", 575, 800),
        device("ipad-pro-11-portrait", "iPad Pro 11"),
        device("ipad-pro-11-landscape", "iPad Pro 11 landscape"),
    ],
};

export function viewportsFor(profile) {
    const wanted = selectedViewportNames();
    return VIEWPORTS[profile].filter((viewport) => !wanted || wanted.has(viewport.name));
}

// quick: light everywhere, dark only on one desktop and one phone viewport; full: both everywhere.
const QUICK_DARK = new Set(["desktop-1280x720", "phone-390x844"]);
export function themesFor(profile, viewport) {
    return profile === "full" || QUICK_DARK.has(viewport.name) ? ["light", "dark"] : ["light"];
}

export function pagesFor() {
    const wanted = selectedPageIds();
    return PAGES.filter((page) => !wanted || wanted.has(page.id));
}

// Context options of a viewport entry. A device descriptor brings viewport, scale, touch and user agent.
export function contextOptions(viewport, theme) {
    if (viewport.device) {
        const descriptor = devices[viewport.device];
        if (!descriptor) throw new Error(`Playwright has no device descriptor ${JSON.stringify(viewport.device)}`);
        return { ...descriptor, colorScheme: theme };
    }
    return { viewport: { width: viewport.width, height: viewport.height }, colorScheme: theme };
}

// ---------------------------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------------------------

// Opens a page and waits for a rendered, settled state. Loading indicators and fonts are observed
// instead of sleeping; two animation frames let the layout flush after the last signal.
//
// Firefox quirk: a context-level colorScheme is not applied to these pages (plain http pages get it;
// emulating again after the load does take effect, and the app follows the change event). Passing
// `theme` repeats the emulation after the load for every engine; the context option stays for the others.
export async function openPage(page, app, pageSpec, theme) {
    const response = await page.goto(`${app.url}${pageSpec.path}`, { waitUntil: "load" });
    if (theme) await page.emulateMedia({ colorScheme: theme });
    expect(response?.status(), `${pageSpec.path} status`).toBe(pageSpec.status);
    await expect(page.locator(pageSpec.landmark).first()).toBeVisible();
    await waitSettled(page);
    return response;
}

export async function waitSettled(page) {
    await page.evaluate(() => document.fonts.ready.then(() => undefined));
    await expect.poll(
        () => page.evaluate(() => [...document.querySelectorAll(".spinner-border, [aria-busy='true']")]
            .filter((element) => element.checkVisibility({ opacityProperty: true, visibilityProperty: true })).length),
        { message: "loading indicators still present" },
    ).toBe(0);
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

// ---------------------------------------------------------------------------------------------
// Page errors
// ---------------------------------------------------------------------------------------------

// Console errors that are known and harmless. Starts empty: an entry needs a page id, a pattern and
// a one-line reason, and must be as narrow as the observed message.
export const EXPECTED_CONSOLE = [
    { page: "status", pattern: /^Failed to load resource: the server responded with a status of 404 \(Not Found\)$/, reason: "the disabled status page is itself the 404 response under test" },
];

const isExpected = (pageId, text) => EXPECTED_CONSOLE.some((entry) => entry.page === pageId && entry.pattern.test(text));

// WebKit quirk: it reports a style-src-attr violation (and a matching "Refused to apply a stylesheet"
// console error) for every rendered <select>, although the page has no inline style attribute
// (verified: the violation target is the SELECT element and the HTML contains no style=""). The app's
// strict CSP is intact, so exactly this pair is tolerated in WebKit, one console message per
// <select> violation; anything beyond that count is still reported.
const WEBKIT_CSP_CONSOLE = /^Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' does not appear in the style-src directive of the Content Security Policy\.?$/;

// WebKit quirk: a same-origin fetch/EventSource that a navigation cancels is reported as a page error
// "... due to access control checks" although the origin is the same (no CORS involved); the app then
// logs its own "Network stats error ... Trying to reconnect" line for it. Both are tolerated in WebKit
// only, and the app's line only when such an aborted request was seen on the page.
const WEBKIT_ABORTED_REQUEST = /127\.0\.0\.1:\d+\/(api\/\S+|health|ui\/events\S*) due to access control checks\.?$/;
const WEBKIT_RECONNECT_LINE = /^Network stats error: ApiError: Trying to reconnect/;

// Records page errors, console errors, failed same-origin requests, 429/5xx responses and CSP
// violations into `sink`. Call the returned function before asserting; it appends the violations the
// page saw and returns the sink.
export async function collectPageErrors(page, sink, pageId, origin, browserName = "chromium") {
    // The binding survives navigations, so violations of earlier documents are kept.
    const violations = [];
    await page.exposeFunction("__wbReportCsp", (violation) => violations.push(violation));
    await page.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (event) => {
            const target = event.target instanceof Element ? event.target.tagName : "";
            window.__wbReportCsp({ directive: event.violatedDirective, blocked: event.blockedURI, target });
        });
    });
    const webkitStyleConsole = [];
    let abortedRequests = 0;
    page.on("pageerror", (error) => {
        if (browserName === "webkit" && WEBKIT_ABORTED_REQUEST.test(error.message)) abortedRequests += 1;
        else sink.push(`pageerror: ${error.message}`);
    });
    page.on("console", (message) => {
        if (message.type() !== "error") return;
        const text = message.text();
        if (browserName === "webkit" && WEBKIT_RECONNECT_LINE.test(text) && abortedRequests > 0) return;
        if (browserName === "webkit" && WEBKIT_CSP_CONSOLE.test(text)) webkitStyleConsole.push(text);
        else if (!isExpected(pageId, text)) sink.push(`console.error: ${text}`);
    });
    page.on("requestfailed", (request) => {
        if (request.url().startsWith(origin)) sink.push(`requestfailed: ${request.method()} ${request.url()} ${request.failure()?.errorText ?? ""}`);
    });
    page.on("response", (response) => {
        const status = response.status();
        if (status === 429 || status >= 500) sink.push(`HTTP ${status}: ${response.request().method()} ${response.url()}`);
    });
    return async () => {
        let tolerated = 0;
        for (const violation of violations) {
            if (browserName === "webkit" && violation.directive === "style-src-attr" && violation.target === "SELECT") tolerated += 1;
            else sink.push(`csp: ${violation.directive} blocked ${violation.blocked}${violation.target ? ` on <${violation.target.toLowerCase()}>` : ""}`);
        }
        for (const text of webkitStyleConsole.slice(tolerated)) sink.push(`console.error: ${text}`);
        return sink;
    };
}

// axe findings accepted on a page: { page, rule, selector (substring of the axe target), reason }.
// Starts empty; an entry must be as narrow as the observed node and say why it is not fixed.
export const KNOWN_AXE = [
    // Pre-existing: the muted text of an empty chart/list placeholder is below the 4.5:1 contrast ratio. Remove the
    // entries once the app fixes the colour of .chart-empty-state-text.
    { page: "dashboard", rule: "color-contrast", selector: "#speedtest-chart-empty", reason: "empty-state placeholder text contrast (app CSS, not fixed by this suite)" },
    { page: "dns", rule: "color-contrast", selector: "#top-queried-unavailable", reason: "empty-state placeholder text contrast (app CSS, not fixed by this suite)" },
    { page: "dns", rule: "color-contrast", selector: "#top-blocked-unavailable", reason: "empty-state placeholder text contrast (app CSS, not fixed by this suite)" },
    { page: "dns", rule: "color-contrast", selector: "#log-unavailable", reason: "empty-state placeholder text contrast (app CSS, not fixed by this suite)" },
];

// ---------------------------------------------------------------------------------------------
// Overflow audit
// ---------------------------------------------------------------------------------------------

// Local horizontal scrollers that may be wider than the viewport. Each entry needs a reason.
export const ALLOWED_SCROLL_X = [
    { selector: ".table-responsive", reason: "Bootstrap wrapper that scrolls wide tables inside its own box" },
];

// Runs inside the page: no closure over module scope. Reports whether the document scrolls
// sideways and which unclipped elements extend beyond the viewport.
function measureOverflow({ allowed, limit }) {
    const root = document.documentElement;
    const width = root.clientWidth;
    const offenders = [];
    const describe = (element) => {
        const id = element.id ? `#${element.id}` : "";
        const classes = typeof element.className === "string" && element.className ? `.${element.className.trim().split(/\s+/).slice(0, 3).join(".")}` : "";
        return `${element.tagName.toLowerCase()}${id}${classes}`;
    };
    const clippedByAncestor = (element) => {
        for (let node = element.parentElement; node && node !== document.body && node !== root; node = node.parentElement) {
            if (allowed.some((selector) => node.matches(selector))) return true;
            const style = getComputedStyle(node);
            if (style.display === "none" || style.visibility === "hidden") return true;
            // A scroller (auto/scroll) is an intended local scroll area. hidden/clip only excuses an element when the
            // clipping box ends inside the viewport (a card); a clipper that reaches the viewport edge, such as the
            // app shell, merely cuts the content off at the screen and hides the defect from the document check.
            if (style.overflowX === "auto" || style.overflowX === "scroll") return true;
            if ((style.overflowX === "hidden" || style.overflowX === "clip") && node.getBoundingClientRect().right < width - 1) return true;
        }
        return false;
    };
    for (const element of document.body.querySelectorAll("*")) {
        if (offenders.length >= limit) break;
        const style = getComputedStyle(element);
        if (style.display === "none" || style.visibility === "hidden" || style.position === "fixed") continue;
        const rect = element.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        if (rect.right <= width + 1 && rect.left >= -1) continue;
        if (element.closest(".visually-hidden, .visually-hidden-focusable, .collapse:not(.show), [hidden]")) continue;
        if (clippedByAncestor(element)) continue;
        offenders.push({ element: describe(element), left: Math.round(rect.left), right: Math.round(rect.right) });
    }
    return { clientWidth: width, scrollWidth: root.scrollWidth, offenders };
}

export async function auditPage(page) {
    const report = await page.evaluate(measureOverflow, { allowed: ALLOWED_SCROLL_X.map((entry) => entry.selector), limit: 8 });
    const problems = [];
    if (report.scrollWidth > report.clientWidth + 1) problems.push(`document scrolls sideways: scrollWidth ${report.scrollWidth} > clientWidth ${report.clientWidth}`);
    for (const offender of report.offenders) problems.push(`${offender.element} spans ${offender.left}..${offender.right} px, viewport is ${report.clientWidth} px`);
    return problems;
}

// Proves the audit can fail: a page with an element wider than the viewport must report it and a
// clean control page must not. Used by the mandatory self-test.
export async function auditSelfTest(page) {
    await page.setContent(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
        <body><div id="wide" style="width:3000px;height:20px;background:#888">wide</div></body></html>`);
    const defect = await auditPage(page);
    await page.setContent(`<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"></head>
        <body><div style="max-width:100%;height:20px">fits</div></body></html>`);
    const control = await auditPage(page);
    return { defect, control };
}
