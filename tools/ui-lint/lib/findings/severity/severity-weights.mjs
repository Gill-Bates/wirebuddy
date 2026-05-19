//
// tools/ui-lint/lib/findings/severity/severity-weights.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { SEVERITY_LEVELS } from './severity-levels.mjs';

export const SEVERITY_WEIGHTS = Object.freeze({
    default: {
        [SEVERITY_LEVELS.critical]: 25,
        [SEVERITY_LEVELS.error]: 12,
        [SEVERITY_LEVELS.warning]: 4,
        [SEVERITY_LEVELS.notice]: 2,
        [SEVERITY_LEVELS.info]: 1,
    },
    accessibility: {
        [SEVERITY_LEVELS.critical]: 30,
        [SEVERITY_LEVELS.error]: 15,
        [SEVERITY_LEVELS.warning]: 5,
        [SEVERITY_LEVELS.notice]: 2,
        [SEVERITY_LEVELS.info]: 1,
    },
    visual: {
        [SEVERITY_LEVELS.critical]: 20,
        [SEVERITY_LEVELS.error]: 10,
        [SEVERITY_LEVELS.warning]: 4,
        [SEVERITY_LEVELS.notice]: 2,
        [SEVERITY_LEVELS.info]: 1,
    },
});
