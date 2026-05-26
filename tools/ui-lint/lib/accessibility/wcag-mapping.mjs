//
// tools/ui-lint/lib/accessibility/wcag-mapping.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export const AXE_IMPACT_TO_SEVERITY = {
    critical: 'blocking',
    serious: 'serious',
    moderate: 'warning',
    minor: 'info',
};

export function mapAxeImpactToSeverity(impact) {
    return AXE_IMPACT_TO_SEVERITY[String(impact || '').toLowerCase()] || 'warning';
}
