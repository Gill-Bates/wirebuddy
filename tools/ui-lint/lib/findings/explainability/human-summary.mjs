//
// tools/ui-lint/lib/findings/explainability/human-summary.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildHumanSummary(finding) {
    return finding.message || finding.explanation || finding.type;
}
