//
// tools/ui-lint/lib/config/runtime/evaluate-payloads.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import {
    buildEvaluationPayload as buildEvaluationPayloadFromPolicies,
    buildSerializableConstants as buildSerializableConstantsFromPolicies,
} from './policies.mjs';

export function buildEvaluationPayload(options) {
    return buildEvaluationPayloadFromPolicies(options);
}

export function buildSerializableConstants(options) {
    return buildSerializableConstantsFromPolicies(options);
}

export const UI_EVAL_CONSTANTS = buildSerializableConstants();