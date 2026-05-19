//
// tools/ui-lint/lib/device-runtime/exports/serializable-runtime.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildSerializableRuntime(runtime) {
    return structuredClone(runtime.snapshot());
}