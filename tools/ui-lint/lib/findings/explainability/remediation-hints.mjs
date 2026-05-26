//
// tools/ui-lint/lib/findings/explainability/remediation-hints.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const HINTS = new Map([
    ['horizontal-overflow', 'Apply min-width:0 to the flex child or constrain the overflowing container.'],
    ['click-target-too-small', 'Increase the interactive area to at least the touch target minimum.'],
    ['hidden-interactive', 'Remove hidden interactive elements from the DOM or make them inert.'],
    ['double-scroll-risk', 'Collapse nested scroll regions and keep one scroll owner per axis.'],
]);

export function buildRemediationHint(finding) {
    return finding.remediation || finding.suggestion || HINTS.get(finding.type) || null;
}
