//
// tools/ui-lint/lib/config/accessibility/focus.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { resolveOptionalToken } from '../tokens/resolver.mjs';

export const FOCUS_POLICY = Object.freeze({
    ringWidthPx: resolveOptionalToken('interaction.focusRingWidth', 3, { category: 'accessibility' }),
    settleMs: 700,
    browserTolerancePx: 1,
});