//
// tools/ui-lint/lib/design-tokens/resolver/derived-values.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function deriveTokenValues(tokens) {
    const touchTarget = Math.max(
        tokens.interaction?.touchTargetMin || 44,
        tokens.interaction?.touchTargetComfortable || 48,
    );

    const compactCardPadding = Math.max(8, Math.round((tokens.card?.padding || 24) / 2));

    return {
        interaction: {
            comfortableTouchTarget: touchTarget,
        },
        card: {
            compactPadding: compactCardPadding,
        },
    };
}