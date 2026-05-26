//
// tools/ui-lint/lib/runtime/telemetry/network.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { createConsoleBuffer } from './console.mjs';
import { createPageErrorBuffer } from './page-errors.mjs';
import { createRequestTimeline } from './requests.mjs';
import { recordResponse } from './responses.mjs';

export function createTelemetrySession(page) {
    const consoleEntries = createConsoleBuffer();
    const pageErrors = createPageErrorBuffer();
    const requestFailures = [];
    const badResponses = [];
    const requests = [];
    const timeline = createRequestTimeline();

    const onConsole = (msg) => {
        if (['error', 'warning'].includes(msg.type())) {
            consoleEntries.push({
                type: msg.type(),
                text: msg.text(),
                sourceURL: msg.location()?.url || null,
                timestamp: Date.now(),
            });
        }
    };
    const onPageError = (err) => pageErrors.push({ message: String(err?.message || err), timestamp: Date.now() });
    const onRequest = (req) => {
        const requestId = ++timeline.nextId;
        timeline.byId.set(req, requestId);
        const entry = {
            requestId,
            url: req.url(),
            method: req.method(),
            resourceType: req.resourceType(),
            startTime: Date.now(),
            endTime: null,
            status: null,
            failed: false,
        };
        timeline.items.push(entry);
        requests.push(entry);
    };
    const onRequestFailed = (req) => {
        const requestId = timeline.byId.get(req);
        const entry = timeline.items.find((item) => item.requestId === requestId);
        if (entry) {
            entry.endTime = Date.now();
            entry.failed = true;
        }
        requestFailures.push({
            requestId,
            url: req.url(),
            error: req.failure()?.errorText || 'unknown',
            timestamp: Date.now(),
        });
    };
    const onResponse = (res) => {
        if (res.status() >= 400) {
            badResponses.push({ url: res.url(), status: res.status(), timestamp: Date.now() });
        }
        recordResponse(timeline, res);
    };

    let started = false;
    const start = () => {
        if (started) return;
        started = true;
        page.on('console', onConsole);
        page.on('pageerror', onPageError);
        page.on('request', onRequest);
        page.on('requestfailed', onRequestFailed);
        page.on('response', onResponse);
    };

    const stop = () => {
        if (!started) return;
        started = false;
        page.off('console', onConsole);
        page.off('pageerror', onPageError);
        page.off('request', onRequest);
        page.off('requestfailed', onRequestFailed);
        page.off('response', onResponse);
    };

    const collect = () => ({
        consoleEntries,
        pageErrors,
        requestFailures,
        badResponses,
        requestTimeline: timeline.items,
    });

    start();

    return { start, stop, collect };
}

export function collectConsoleAndNetwork(page) {
    const session = createTelemetrySession(page);
    return () => {
        session.stop();
        return session.collect();
    };
}
