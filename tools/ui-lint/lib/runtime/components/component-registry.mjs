//
// tools/ui-lint/lib/runtime/components/component-registry.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

const captureComponents = new Map();

export function registerCaptureComponent(component) {
    if (!component?.selector || !component?.type) {
        throw new Error('Component registration requires selector and type');
    }

    captureComponents.set(component.type, { ...component });
}

export function getCaptureComponent(type) {
    return captureComponents.get(type) || null;
}

export function getCaptureComponents() {
    return Array.from(captureComponents.values());
}
