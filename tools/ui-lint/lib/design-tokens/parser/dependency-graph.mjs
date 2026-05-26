//
// tools/ui-lint/lib/design-tokens/parser/dependency-graph.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const VAR_REFERENCE_RE = /var\(\s*(--[a-zA-Z0-9-_]+)\s*(?:,([^()]+|\((?:[^()]+|\([^()]*\))*\))*)?\)/g;

export function extractVarReferences(value) {
    if (typeof value !== 'string') return [];
    const references = [];
    let match;
    while ((match = VAR_REFERENCE_RE.exec(value)) !== null) {
        references.push(match[1]);
    }
    VAR_REFERENCE_RE.lastIndex = 0;
    return references;
}

export function buildDependencyGraph(declarations) {
    const graph = new Map();

    for (const declaration of declarations) {
        graph.set(declaration.name, new Set(extractVarReferences(declaration.value)));
    }

    return graph;
}

export function detectCircularDependencies(graph) {
    const visited = new Set();
    const active = new Set();
    const cycles = [];

    const visit = (tokenName, path = []) => {
        if (active.has(tokenName)) {
            const cycleStart = path.indexOf(tokenName);
            cycles.push(path.slice(cycleStart).concat(tokenName));
            return;
        }
        if (visited.has(tokenName)) return;

        visited.add(tokenName);
        active.add(tokenName);
        const dependencies = graph.get(tokenName) || new Set();
        for (const dependency of dependencies) {
            visit(dependency, [...path, tokenName]);
        }
        active.delete(tokenName);
    };

    for (const tokenName of graph.keys()) {
        visit(tokenName);
    }

    return cycles;
}