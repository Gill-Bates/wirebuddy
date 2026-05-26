//
// tools/ui-lint/lib/view-orchestration/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { LOGIN_FAILURE_VIEW_DEFS, VIEW_DEFS } from './catalog.mjs';
import { adaptiveCoverageExpansion } from './planner.mjs';

export {
    VIEW_RUNTIME_VERSION,
    VIEW_DEFS,
    LOGIN_FAILURE_VIEW_DEFS,
    VIEW_FAMILIES,
    DEVICE_ORDER,
    LOGIN_DEVICE_ORDER,
    THEMES,
} from './catalog.mjs';

export {
    adaptiveCoverageExpansion,
    buildViewExecutionAnalytics,
    clearViewProviders,
    composeViewExecutionPlan,
    createViewExecutionGraph,
    discoverViews,
    expandCoverage,
    registerViewProvider,
    validateViewDefinition,
    whyWasViewScheduled,
} from './planner.mjs';

export { expandCoverage as expandViewDefinitions } from './planner.mjs';

export const VIEWS = adaptiveCoverageExpansion(VIEW_DEFS);
export const LOGIN_FAILURE_VIEWS = adaptiveCoverageExpansion(LOGIN_FAILURE_VIEW_DEFS);
