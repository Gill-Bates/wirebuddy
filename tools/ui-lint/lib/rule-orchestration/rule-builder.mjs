//
// tools/ui-lint/lib/rule-orchestration/rule-builder.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

function buildRuleTemplate({ id, name, category, description, run, meta = {} }) {
    return {
        id,
        name,
        category,
        description,
        run,
        meta: {
            ...meta,
            id: meta.id || id,
            category: meta.category || category,
        },
    };
}

export const RuleBuilder = {
    accessibility(id, name, run) {
        return buildRuleTemplate({
            id,
            name,
            category: 'accessibility',
            description: `Accessibility check: ${name}`,
            run,
        });
    },
    layout(id, name, run) {
        return buildRuleTemplate({
            id,
            name,
            category: 'layout',
            description: `Layout check: ${name}`,
            run,
        });
    },
    mobile(id, name, run) {
        return buildRuleTemplate({
            id,
            name,
            category: 'mobile',
            description: `Mobile/iOS check: ${name}`,
            run,
        });
    },
    component(id, name, run) {
        return buildRuleTemplate({
            id,
            name,
            category: 'component',
            description: `Component check: ${name}`,
            run,
        });
    },
    performance(id, name, run) {
        return buildRuleTemplate({
            id,
            name,
            category: 'performance',
            description: `Performance check: ${name}`,
            run,
        });
    },
};
