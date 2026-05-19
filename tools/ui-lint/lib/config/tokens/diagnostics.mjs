//
// tools/ui-lint/lib/config/tokens/diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function createTokenDiagnostics(resolution) {
    return {
        sourceToken: resolution.sourceToken,
        fallbackUsed: Boolean(resolution.fallbackUsed),
        version: resolution.version ?? 1,
        category: resolution.category ?? 'general',
        rawValue: resolution.rawValue,
        resolvedValue: resolution.value,
    };
}