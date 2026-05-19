//
// tools/ui-lint/lib/runtime/runtime/lifecycle.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { createTelemetrySession } from '../telemetry/network.mjs';
import { createCleanupBucket } from './cleanup.mjs';
import { buildRuntimeDiagnostics } from './diagnostics.mjs';

const RUNTIME_KEY = Symbol.for('uiLint.runtime');

export function createRuntime(page, metadata = {}) {
    const cleanup = createCleanupBucket();
    const telemetry = createTelemetrySession(page);
    const runtime = {
        version: 1,
        metadata,
        telemetry,
        cleanup,
        start() {
            telemetry.start();
        },
        collect() {
            return {
                diagnostics: buildRuntimeDiagnostics(window[RUNTIME_KEY] || {}),
                telemetry: telemetry.collect(),
            };
        },
        async dispose() {
            telemetry.stop();
            await cleanup.dispose();
        },
    };

    return runtime;
}
