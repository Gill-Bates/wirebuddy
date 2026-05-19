//
// tools/ui-lint/lib/runtime-orchestration/runtime-state-store.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createRuntimeStateStore() {
    const sessions = new Map();

    return {
        create(sessionId, runtimeContext) {
            const record = {
                sessionId,
                runtimeId: runtimeContext.runtimeId,
                sandboxId: runtimeContext.sandboxId,
                createdAt: new Date().toISOString(),
                status: 'active',
                runtimeContext,
            };
            sessions.set(sessionId, record);
            return record;
        },
        get(sessionId) {
            return sessions.get(sessionId) || null;
        },
        list() {
            return [...sessions.values()];
        },
        close(sessionId, status = 'closed') {
            const record = sessions.get(sessionId);
            if (!record) return null;
            record.status = status;
            record.closedAt = new Date().toISOString();
            return record;
        },
        snapshot() {
            return this.list();
        },
    };
}
