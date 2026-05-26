//
// tools/ui-lint/lib/runtime-config.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export {
    RUNTIME_VERSION,
    RUNTIME_PROFILES,
    listRuntimeProfiles,
    resolveRuntimeProfile,
    whyWasThisProfileChosen,
    buildRunPaths,
    createRuntimeContext,
    getBaseContextOptions,
    getAuthenticatedContextOptions,
    getLoginFailureContextOptions,
} from './runtime-orchestration/index.mjs';
