//
// tools/ui-lint/lib/runtime/runtime/cleanup.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createCleanupBucket() {
    const callbacks = [];

    return {
        add(callback) {
            if (typeof callback === 'function') callbacks.push(callback);
        },
        async dispose() {
            while (callbacks.length > 0) {
                const callback = callbacks.pop();
                await callback();
            }
        },
    };
}
