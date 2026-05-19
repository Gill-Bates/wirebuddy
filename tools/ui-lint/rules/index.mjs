//
// tools/ui-lint/rules/index.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//
// Rule index - imports and registers all lint rules.
//

// Accessibility rules
import './accessibility/click-targets.mjs';
import './accessibility/focus-indicators.mjs';

// Layout rules
import './layout/overflow.mjs';

// Mobile rules
import './mobile/scroll-traps.mjs';

// Export registry functions for convenience
export {
    getAllRules,
    getCategories,
    getRulesByCategory,
    runRule,
    runRules,
    runCategory,
    runAllRules,
    createContext,
} from '../lib/rule-registry.mjs';

export { collectDOMSnapshot } from '../lib/dom-snapshot.mjs';
export { tokens, loadDesignTokens } from '../lib/design-tokens.mjs';
