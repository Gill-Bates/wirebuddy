//
// tools/ui-lint/lib/findings/policies/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { buildAccessibilityPolicy } from './accessibility-policy.mjs';
import { buildDashboardPolicy } from './dashboard-policy.mjs';
import { buildLayoutPolicy } from './layout-policy.mjs';
import { buildNetworkPolicy } from './network-policy.mjs';
import { buildUsersPolicy } from './users-policy.mjs';
import { buildVisualPolicy } from './visual-policy.mjs';

export function buildFindingPolicies() {
    return [
        buildAccessibilityPolicy(),
        buildLayoutPolicy(),
        buildVisualPolicy(),
        buildDashboardPolicy(),
        buildUsersPolicy(),
        buildNetworkPolicy(),
    ];
}
