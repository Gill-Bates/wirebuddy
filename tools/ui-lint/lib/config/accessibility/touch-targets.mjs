//
// tools/ui-lint/lib/config/accessibility/touch-targets.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { resolveOptionalToken } from '../tokens/resolver.mjs';

export const TOUCH_TARGET_POLICY = Object.freeze({
    minSizePx: resolveOptionalToken('interaction.touchTargetMin', 44, { category: 'accessibility' }),
    comfortableSizePx: resolveOptionalToken('interaction.touchTargetComfortable', 48, { category: 'accessibility' }),
});

export const CLICK_TARGET_MIN_SIZE_PX = TOUCH_TARGET_POLICY.minSizePx;

export const INPUT_GROUP_HEIGHT_EXPECTED_PX = resolveOptionalToken('form.inputHeight', 38, {
    category: 'accessibility',
});

export const INPUT_GROUP_HEIGHT_TOLERANCE_PX = 2;

export const STANDARD_BUTTON_HEIGHT_EXPECTED_PX = resolveOptionalToken('form.inputHeight', 38, {
    category: 'accessibility',
});

export const STANDARD_BUTTON_HEIGHT_TOLERANCE_PX = 2;