//
// tools/ui-lint/lib/design-tokens/parser/ast-normalizer.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

export function normalizeCssAst(root) {
    if (!root || root.type !== 'root') {
        throw new TypeError('Expected a PostCSS root node');
    }

    root.walkComments((comment) => {
        comment.remove();
    });

    return root;
}