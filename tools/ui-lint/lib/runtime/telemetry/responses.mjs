//
// tools/ui-lint/lib/runtime/telemetry/responses.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function recordResponse(timeline, response) {
    const request = response.request();
    const requestId = timeline.byId.get(request);
    if (requestId == null) return;

    const entry = timeline.items.find((item) => item.requestId === requestId);
    if (!entry) return;

    entry.endTime = Date.now();
    entry.status = response.status();
    entry.ok = response.ok();
}
