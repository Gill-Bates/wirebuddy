//
// tools/ui-lint/lib/dom-runtime/collections/semantic-groups.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function buildSemanticGroups(nodes) {
    const groups = {
        navigation: [],
        forms: [],
        dialogs: [],
        overlays: [],
        dataTables: [],
    };

    for (const node of nodes) {
        const role = node.accessibility?.computedRole || node.role || '';
        const tag = (node.tag || '').toLowerCase();

        if (role === 'navigation' || tag === 'nav') groups.navigation.push(node);
        if (['form', 'input', 'select', 'textarea', 'button'].includes(tag) || /textbox|combobox|button/.test(role)) groups.forms.push(node);
        if (role === 'dialog' || tag === 'dialog') groups.dialogs.push(node);
        if (node.positioning?.fixed || node.positioning?.sticky || role === 'alertdialog') groups.overlays.push(node);
        if (tag === 'table' || role === 'table' || role === 'grid') groups.dataTables.push(node);
    }

    return groups;
}
