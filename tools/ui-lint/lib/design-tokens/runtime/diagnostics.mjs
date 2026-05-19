//
// tools/ui-lint/lib/design-tokens/runtime/diagnostics.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildRuntimeDiagnostics(snapshot) {
    return {
        source: snapshot.source,
        sourceHash: snapshot.sourceHash,
        provider: snapshot.provider,
        fallbackUsage: snapshot.diagnostics?.fallbackUsage || [],
        missingTokens: snapshot.diagnostics?.missingTokens || [],
        unknownTokens: snapshot.diagnostics?.unknownTokens || [],
        unresolvedVars: snapshot.diagnostics?.unresolvedVars || [],
        circularDependencies: snapshot.circularDependencies || [],
        deprecatedAliases: snapshot.diagnostics?.deprecatedAliases || [],
    };
}