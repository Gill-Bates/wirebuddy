//
// app/static/js/core/dom.js
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

// Deterministic UI runtime for declarative DOM construction, scheduling,
// diffing, reactivity, lifecycle management, and compatibility helpers.

(function () {
    'use strict';

    const FRAGMENT = Symbol('WB.Fragment');
    const PORTAL = Symbol('WB.Portal');
    const CONTEXT_PROVIDER = Symbol('WB.ContextProvider');
    const PRIORITY_ORDER = Object.freeze({ high: 0, normal: 1, low: 2, idle: 3 });

    const runtime = {
        renderQueue: [],
        layoutQueue: [],
        effectQueue: [],
        scheduled: false,
        metrics: {
            renderDuration: 0,
            mutationCount: 0,
            reflowCount: 0,
            commitCount: 0,
            detachedNodes: 0,
            errorCount: 0,
            lastCommitAt: null,
        },
        plugins: new Set(),
        renderHooks: {
            start: new Set(),
            commit: new Set(),
            error: new Set(),
        },
        disposables: {
            timers: new Set(),
            observers: new Set(),
            listeners: new Set(),
        },
        nodeCleanups: new WeakMap(),
        detachedNodes: new Set(),
        roots: new WeakMap(),
        delegatedHandlers: new WeakMap(),
        delegatedEventTypes: new Set(),
        targetMap: new WeakMap(),
        proxyCache: new WeakMap(),
        effects: new Set(),
        currentEffect: null,
        effectStack: [],
        componentStack: [],
        contextStack: [],
        componentId: 0,
        nodeId: 0,
        preserveStateOnReloadFlag: false,
    };

    function now() {
        return (window.performance && typeof window.performance.now === 'function') ? window.performance.now() : Date.now();
    }

    function isNode(value) {
        return typeof Node !== 'undefined' && value instanceof Node;
    }

    function isVNode(value) {
        return Boolean(value && typeof value === 'object' && value.__wbVNode === true);
    }

    function isPlainObject(value) {
        return Boolean(value && typeof value === 'object' && !Array.isArray(value) && !isNode(value) && !isVNode(value));
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str ?? '';
        return div.innerHTML;
    }

    function hashId(str) {
        if (!str) return 'empty';
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash).toString(36);
    }

    function sanitizeHtml(html) {
        const template = document.createElement('template');
        template.innerHTML = String(html ?? '');

        const forbiddenTags = new Set(['script', 'iframe', 'object', 'embed', 'link', 'meta']);
        const walker = document.createTreeWalker(template.content, NodeFilter.SHOW_ELEMENT);
        const nodes = [];

        while (walker.nextNode()) {
            nodes.push(walker.currentNode);
        }

        for (const node of nodes) {
            if (forbiddenTags.has(node.tagName.toLowerCase())) {
                node.remove();
                continue;
            }

            for (const attr of [...node.attributes]) {
                const name = attr.name.toLowerCase();
                const value = attr.value || '';
                if (name.startsWith('on')) {
                    node.removeAttribute(attr.name);
                } else if ((name === 'href' || name === 'src' || name === 'xlink:href') && /^javascript:/i.test(value.trim())) {
                    node.removeAttribute(attr.name);
                }
            }
        }

        return template.innerHTML;
    }

    let trustedHtmlPolicy = null;
    function getTrustedHtmlPolicy() {
        if (trustedHtmlPolicy !== null) {
            return trustedHtmlPolicy;
        }

        if (window.trustedTypes?.createPolicy) {
            try {
                trustedHtmlPolicy = window.trustedTypes.createPolicy('wb-dom', {
                    createHTML: sanitizeHtml,
                });
            } catch (_) {
                trustedHtmlPolicy = false;
            }
        } else {
            trustedHtmlPolicy = false;
        }

        return trustedHtmlPolicy || null;
    }

    function safeHtml(html) {
        const policy = getTrustedHtmlPolicy();
        const sanitized = sanitizeHtml(html);
        return policy ? policy.createHTML(sanitized) : sanitized;
    }

    function normalizeChildrenInput(children) {
        const normalized = [];

        const push = (value) => {
            if (value == null || value === false || value === true) {
                return;
            }

            if (Array.isArray(value)) {
                for (const item of value) {
                    push(item);
                }
                return;
            }

            normalized.push(normalizeVNode(value));
        };

        push(children);
        return normalized;
    }

    function normalizeProps(props = {}) {
        const next = { ...props };
        if ('children' in next) delete next.children;
        return next;
    }

    function createTextVNode(text) {
        return {
            __wbVNode: true,
            type: '#text',
            key: null,
            props: {},
            children: [],
            text: String(text),
            el: null,
            ownerId: null,
        };
    }

    function createFragmentVNode(children = [], key = null) {
        return {
            __wbVNode: true,
            type: FRAGMENT,
            key,
            props: {},
            children: normalizeChildrenInput(children),
            el: null,
            end: null,
            ownerId: null,
        };
    }

    function normalizeVNode(value) {
        if (value == null || value === false || value === true) {
            return createFragmentVNode([]);
        }

        if (isVNode(value)) {
            return value;
        }

        if (isNode(value)) {
            return {
                __wbVNode: true,
                type: '#node',
                key: null,
                props: {},
                children: [],
                node: value,
                el: value,
                ownerId: null,
            };
        }

        if (Array.isArray(value)) {
            return createFragmentVNode(value);
        }

        if (typeof value === 'string' || typeof value === 'number') {
            return createTextVNode(value);
        }

        return value;
    }

    function h(type, props = {}, children = []) {
        const resolvedProps = normalizeProps(props);
        const resolvedChildren = arguments.length >= 3 ? children : props.children;

        return {
            __wbVNode: true,
            type,
            key: props.key ?? null,
            props: resolvedProps,
            children: normalizeChildrenInput(resolvedChildren),
            el: null,
            end: null,
            ownerId: null,
        };
    }

    function createSignal(initialValue, options = {}) {
        const cell = { value: initialValue };
        const equals = typeof options.equals === 'function' ? options.equals : Object.is;

        const getter = () => {
            track(cell, 'value');
            return cell.value;
        };

        const setter = (nextValue) => {
            const resolved = typeof nextValue === 'function' ? nextValue(cell.value) : nextValue;
            if (equals(cell.value, resolved)) {
                return cell.value;
            }

            cell.value = resolved;
            trigger(cell, 'value');
            return cell.value;
        };

        return [getter, setter];
    }

    function createReactive(target) {
        if (!isPlainObject(target) && !Array.isArray(target)) {
            return target;
        }

        if (runtime.proxyCache.has(target)) {
            return runtime.proxyCache.get(target);
        }

        const proxy = new Proxy(target, {
            get(obj, key, receiver) {
                if (key === '__raw__') {
                    return obj;
                }

                track(obj, key);
                const value = Reflect.get(obj, key, receiver);
                return isPlainObject(value) || Array.isArray(value) ? createReactive(value) : value;
            },
            set(obj, key, value, receiver) {
                const previous = obj[key];
                const ok = Reflect.set(obj, key, value, receiver);
                if (!Object.is(previous, value)) {
                    trigger(obj, key);
                }
                return ok;
            },
            deleteProperty(obj, key) {
                const hadKey = Object.prototype.hasOwnProperty.call(obj, key);
                const ok = Reflect.deleteProperty(obj, key);
                if (hadKey) {
                    trigger(obj, key);
                }
                return ok;
            },
        });

        runtime.proxyCache.set(target, proxy);
        return proxy;
    }

    function createStore(initialState = {}) {
        const state = createReactive(structuredCloneSafe(initialState));

        const setStore = (patch) => {
            if (typeof patch === 'function') {
                const result = patch(state);
                if (isPlainObject(result)) {
                    Object.assign(state, result);
                }
                return state;
            }

            if (isPlainObject(patch)) {
                Object.assign(state, patch);
            }

            return state;
        };

        return [state, setStore];
    }

    function computed(fn) {
        const [value, setValue] = createSignal(undefined);
        effect(() => setValue(fn()));
        return value;
    }

    function structuredCloneSafe(value) {
        if (typeof structuredClone === 'function') {
            try {
                return structuredClone(value);
            } catch (_) {
                return value;
            }
        }
        return Array.isArray(value) ? value.slice() : (isPlainObject(value) ? { ...value } : value);
    }

    function cleanupEffect(effectRecord) {
        for (const dep of effectRecord.deps) {
            dep.delete(effectRecord);
        }
        effectRecord.deps.clear();

        if (typeof effectRecord.cleanup === 'function') {
            try {
                effectRecord.cleanup();
            } catch (error) {
                handleRuntimeError(error);
            }
            effectRecord.cleanup = null;
        }
    }

    function runEffect(effectRecord) {
        if (effectRecord.disposed) {
            return;
        }

        cleanupEffect(effectRecord);

        runtime.effectStack.push(effectRecord);
        runtime.currentEffect = effectRecord;
        try {
            const result = effectRecord.fn();
            if (typeof result === 'function') {
                effectRecord.cleanup = result;
            }
        } finally {
            runtime.effectStack.pop();
            runtime.currentEffect = runtime.effectStack[runtime.effectStack.length - 1] || null;
        }
    }

    function effect(fn, options = {}) {
        const effectRecord = {
            id: ++runtime.nodeId,
            fn,
            deps: new Set(),
            cleanup: null,
            disposed: false,
            queued: false,
            priority: options.priority || 'normal',
            scope: runtime.componentStack[runtime.componentStack.length - 1] || null,
        };

        effectRecord.disposer = () => {
            if (effectRecord.disposed) {
                return;
            }
            effectRecord.disposed = true;
            cleanupEffect(effectRecord);
        };

        runtime.effects.add(effectRecord);
        runEffect(effectRecord);

        if (effectRecord.scope) {
            registerScopeCleanup(effectRecord.scope, effectRecord.disposer);
        }

        return effectRecord.disposer;
    }

    function track(target, key) {
        const effectRecord = runtime.currentEffect;
        if (!effectRecord) {
            return;
        }

        let keyMap = runtime.targetMap.get(target);
        if (!keyMap) {
            keyMap = new Map();
            runtime.targetMap.set(target, keyMap);
        }

        let dep = keyMap.get(key);
        if (!dep) {
            dep = new Set();
            keyMap.set(key, dep);
        }

        if (!dep.has(effectRecord)) {
            dep.add(effectRecord);
            effectRecord.deps.add(dep);
        }
    }

    function trigger(target, key) {
        const keyMap = runtime.targetMap.get(target);
        if (!keyMap) {
            return;
        }

        const dep = keyMap.get(key);
        if (!dep) {
            return;
        }

        for (const effectRecord of dep) {
            if (!effectRecord.disposed) {
                scheduleEffectRunner(effectRecord);
            }
        }
    }

    function scheduleEffectRunner(effectRecord) {
        if (effectRecord.queued || effectRecord.disposed) {
            return;
        }

        effectRecord.queued = true;
        queueEffect(() => {
            effectRecord.queued = false;
            runEffect(effectRecord);
        }, effectRecord.priority || 'normal');
    }

    function addDisposable(type, value) {
        if (type === 'timer') {
            runtime.disposables.timers.add(value);
        } else if (type === 'observer') {
            runtime.disposables.observers.add(value);
        } else if (type === 'listener') {
            runtime.disposables.listeners.add(value);
        }

        return value;
    }

    function disposeTimers() {
        for (const timerId of runtime.disposables.timers) {
            clearTimeout(timerId);
            clearInterval(timerId);
        }
        runtime.disposables.timers.clear();
    }

    function disposeObservers() {
        for (const observer of runtime.disposables.observers) {
            try {
                observer.disconnect();
            } catch (_) {
                // ignore observer teardown failures
            }
        }
        runtime.disposables.observers.clear();
    }

    function disposeListeners() {
        for (const listener of runtime.disposables.listeners) {
            try {
                listener.target.removeEventListener(listener.type, listener.handler, listener.options);
            } catch (_) {
                // ignore listener teardown failures
            }
        }
        runtime.disposables.listeners.clear();
    }

    function registerScopeCleanup(scope, cleanup) {
        if (!scope) {
            return;
        }

        if (!scope.cleanups) {
            scope.cleanups = new Set();
        }

        scope.cleanups.add(cleanup);
    }

    function runScopeCleanups(scope) {
        if (!scope?.cleanups) {
            return;
        }

        for (const cleanup of scope.cleanups) {
            try {
                cleanup();
            } catch (error) {
                handleRuntimeError(error);
            }
        }

        scope.cleanups.clear();
    }

    function onMount(fn) {
        const scope = runtime.componentStack[runtime.componentStack.length - 1];
        if (!scope) {
            throw new Error('onMount() must be called during component rendering');
        }

        scope.mounts.push(fn);
        return () => {
            const index = scope.mounts.indexOf(fn);
            if (index >= 0) {
                scope.mounts.splice(index, 1);
            }
        };
    }

    function onUnmount(fn) {
        const scope = runtime.componentStack[runtime.componentStack.length - 1];
        if (!scope) {
            throw new Error('onUnmount() must be called during component rendering');
        }

        scope.unmounts.push(fn);
        return () => {
            const index = scope.unmounts.indexOf(fn);
            if (index >= 0) {
                scope.unmounts.splice(index, 1);
            }
        };
    }

    function onCleanup(fn) {
        const effectRecord = runtime.currentEffect;
        const scope = runtime.componentStack[runtime.componentStack.length - 1];

        if (effectRecord) {
            const previousCleanup = effectRecord.cleanup;
            effectRecord.cleanup = typeof previousCleanup === 'function'
                ? () => {
                    previousCleanup();
                    fn();
                }
                : fn;
            return fn;
        }

        if (scope) {
            registerScopeCleanup(scope, fn);
            return fn;
        }

        throw new Error('onCleanup() must be called during component rendering or an active effect');
    }

    function createContext(defaultValue) {
        const context = {
            id: `wb-context-${++runtime.nodeId}`,
            defaultValue,
        };

        context.Provider = function Provider(props = {}) {
            return h(CONTEXT_PROVIDER, { context, value: props.value ?? defaultValue }, props.children ?? []);
        };

        return context;
    }

    function useContext(context) {
        for (let index = runtime.contextStack.length - 1; index >= 0; index--) {
            const frame = runtime.contextStack[index];
            if (frame.has(context.id)) {
                return frame.get(context.id);
            }
        }

        return context.defaultValue;
    }

    function createComponentScope(vnode) {
        return {
            id: `wb-component-${++runtime.componentId}`,
            vnode,
            mounts: [],
            unmounts: [],
            cleanups: new Set(),
            effects: new Set(),
            contexts: new Map(runtime.contextStack[runtime.contextStack.length - 1] || []),
            subtree: null,
            el: null,
        };
    }

    function disposeVNode(vnode) {
        if (!vnode) {
            return;
        }

        if (vnode.type === '#text' || vnode.type === '#node') {
            disposeNode(vnode.el || vnode.node);
            return;
        }

        if (vnode.type === FRAGMENT) {
            for (const child of vnode.children || []) {
                disposeVNode(child);
            }
            disposeNode(vnode.el);
            disposeNode(vnode.end);
            return;
        }

        if (vnode.type === PORTAL) {
            for (const child of vnode.children || []) {
                disposeVNode(child);
            }
            return;
        }

        if (typeof vnode.type === 'function') {
            const scope = vnode.scope;
            if (scope) {
                for (const cleanup of scope.unmounts) {
                    try {
                        cleanup();
                    } catch (error) {
                        handleRuntimeError(error);
                    }
                }
                runScopeCleanups(scope);
                for (const effectRecord of scope.effects) {
                    effectRecord.disposer();
                }
                scope.effects.clear();
            }

            disposeVNode(vnode.subtree);
            return;
        }

        for (const child of vnode.children || []) {
            disposeVNode(child);
        }

        disposeNode(vnode.el);
    }

    function disposeNode(node) {
        if (!node) {
            return;
        }

        const cleanups = runtime.nodeCleanups.get(node);
        if (cleanups) {
            for (const cleanup of cleanups) {
                try {
                    cleanup();
                } catch (error) {
                    handleRuntimeError(error);
                }
            }
            runtime.nodeCleanups.delete(node);
        }

        runtime.detachedNodes.add(node);
        runtime.metrics.detachedNodes = runtime.detachedNodes.size;
    }

    function registerNodeCleanup(node, cleanup) {
        if (!node || typeof cleanup !== 'function') {
            return;
        }

        let cleanups = runtime.nodeCleanups.get(node);
        if (!cleanups) {
            cleanups = new Set();
            runtime.nodeCleanups.set(node, cleanups);
        }

        cleanups.add(cleanup);
    }

    function ensureDelegatedEvent(type) {
        if (runtime.delegatedEventTypes.has(type)) {
            return;
        }

        document.addEventListener(type, dispatchDelegatedEvent, true);
        runtime.delegatedEventTypes.add(type);
    }

    function registerDelegatedHandler(node, type, handler) {
        if (!isNode(node) || typeof handler !== 'function') {
            return;
        }

        let map = runtime.delegatedHandlers.get(node);
        if (!map) {
            map = new Map();
            runtime.delegatedHandlers.set(node, map);
        }

        map.set(type, handler);
        ensureDelegatedEvent(type);
    }

    function dispatchDelegatedEvent(event) {
        const path = typeof event.composedPath === 'function' ? event.composedPath() : null;
        const nodes = path && path.length ? path : buildEventPath(event.target);

        for (const node of nodes) {
            if (!isNode(node)) {
                continue;
            }

            const map = runtime.delegatedHandlers.get(node);
            const handler = map?.get(event.type);
            if (handler) {
                handler.call(node, event);
                if (event.cancelBubble) {
                    break;
                }
            }
        }
    }

    function buildEventPath(target) {
        const nodes = [];
        let current = target;

        while (current) {
            nodes.push(current);
            current = current.parentNode || current.host || null;
        }

        return nodes;
    }

    function notifyRenderStart() {
        for (const callback of runtime.renderHooks.start) {
            try {
                callback(runtime.metrics);
            } catch (error) {
                handleRuntimeError(error);
            }
        }

        for (const plugin of runtime.plugins) {
            try {
                plugin.onRenderStart?.(runtime.metrics);
            } catch (error) {
                handleRuntimeError(error);
            }
        }
    }

    function notifyCommit() {
        for (const callback of runtime.renderHooks.commit) {
            try {
                callback(runtime.metrics);
            } catch (error) {
                handleRuntimeError(error);
            }
        }

        for (const plugin of runtime.plugins) {
            try {
                plugin.onCommit?.(runtime.metrics);
            } catch (error) {
                handleRuntimeError(error);
            }
        }
    }

    function notifyError(error) {
        for (const callback of runtime.renderHooks.error) {
            try {
                callback(error);
            } catch (_) {
                // ignore hook failures
            }
        }

        for (const plugin of runtime.plugins) {
            try {
                plugin.onError?.(error);
            } catch (_) {
                // ignore plugin failures
            }
        }
    }

    function handleRuntimeError(error) {
        runtime.metrics.errorCount += 1;
        notifyError(error);
        console.error('[WBDom] runtime error:', error);
    }

    function enqueueTask(queue, task, priority = 'normal') {
        const entry = {
            task,
            priority: PRIORITY_ORDER[priority] ?? PRIORITY_ORDER.normal,
            order: ++runtime.nodeId,
        };

        queue.push(entry);
        queue.sort((left, right) => left.priority - right.priority || left.order - right.order);
        scheduleFlush();
        return entry;
    }

    function scheduleDOMMutation(task, priority = 'normal') {
        return new Promise((resolve, reject) => {
            enqueueTask(runtime.renderQueue, {
                run() {
                    try {
                        resolve(task());
                    } catch (error) {
                        reject(error);
                        throw error;
                    }
                },
            }, priority);
        });
    }

    function queueLayout(task, priority = 'normal') {
        enqueueTask(runtime.layoutQueue, { run: task }, priority);
    }

    function queueEffect(task, priority = 'normal') {
        enqueueTask(runtime.effectQueue, { run: task }, priority);
    }

    function scheduleFlush() {
        if (runtime.scheduled) {
            return;
        }

        runtime.scheduled = true;
        queueMicrotask(flushScheduler);
    }

    function flushPhase(queue) {
        while (queue.length) {
            const entry = queue.shift();
            try {
                entry.task.run();
            } catch (error) {
                handleRuntimeError(error);
            }
        }
    }

    function flushScheduler() {
        runtime.scheduled = false;
        const startedAt = now();

        notifyRenderStart();
        flushPhase(runtime.renderQueue);
        runtime.metrics.commitCount += 1;
        runtime.metrics.lastCommitAt = new Date().toISOString();

        flushPhase(runtime.layoutQueue);
        flushPhase(runtime.effectQueue);

        runtime.metrics.renderDuration = now() - startedAt;
        notifyCommit();

        if (runtime.renderQueue.length || runtime.layoutQueue.length || runtime.effectQueue.length) {
            scheduleFlush();
        }
    }

    function getNodeForVNode(vnode) {
        if (!vnode) {
            return null;
        }

        if (vnode.type === '#text' || vnode.type === '#node') {
            return vnode.el || vnode.node || null;
        }

        if (vnode.type === FRAGMENT) {
            return vnode.el || null;
        }

        if (vnode.type === PORTAL) {
            return vnode.el || null;
        }

        if (typeof vnode.type === 'function') {
            return vnode.el || null;
        }

        return vnode.el || null;
    }

    function sameVNodeType(left, right) {
        return Boolean(left && right && left.type === right.type && left.key === right.key);
    }

    function setClassName(elm, className) {
        if (className == null || className === false) {
            elm.removeAttribute('class');
            return;
        }

        elm.className = String(className);
    }

    function setAttributes(elm, attrs = {}, previousAttrs = {}) {
        for (const [key, value] of Object.entries(previousAttrs)) {
            if (!(key in attrs)) {
                elm.removeAttribute(key);
            }
        }

        for (const [key, value] of Object.entries(attrs)) {
            if (value === true) {
                elm.setAttribute(key, '');
            } else if (value === false || value == null) {
                elm.removeAttribute(key);
            } else {
                elm.setAttribute(key, String(value));
            }
        }
    }

    function setDataAttributes(elm, data = {}, previousData = {}) {
        for (const key of Object.keys(previousData)) {
            if (!(key in data)) {
                delete elm.dataset[key];
            }
        }

        for (const [key, value] of Object.entries(data)) {
            if (value == null || value === false) {
                delete elm.dataset[key];
            } else {
                elm.dataset[key] = String(value);
            }
        }
    }

    function setStyles(elm, style = {}, previousStyle = {}) {
        for (const key of Object.keys(previousStyle)) {
            if (!(key in style)) {
                elm.style[key] = '';
            }
        }

        for (const [key, value] of Object.entries(style)) {
            elm.style[key] = value == null ? '' : String(value);
        }
    }

    function setDelegatedListeners(elm, listeners = {}, previousListeners = {}) {
        for (const [event, handler] of Object.entries(previousListeners)) {
            if (!(event in listeners)) {
                const map = runtime.delegatedHandlers.get(elm);
                map?.delete(event);
            }
        }

        for (const [event, handler] of Object.entries(listeners)) {
            registerDelegatedHandler(elm, event, handler);
        }
    }

    function clearChildren(element) {
        while (element.firstChild) {
            disposeNode(element.firstChild);
            element.removeChild(element.firstChild);
            runtime.metrics.mutationCount += 1;
        }
    }

    function replaceContent(parent, children) {
        clearChildren(parent);
        for (const child of children) {
            if (isNode(child)) {
                parent.appendChild(child);
                runtime.metrics.mutationCount += 1;
            }
        }
    }

    function fragment(elements) {
        const frag = document.createDocumentFragment();
        for (const elem of elements) {
            if (isNode(elem)) {
                frag.appendChild(elem);
            }
        }
        return frag;
    }

    function applyElementProps(elm, nextProps = {}, previousProps = {}) {
        if ('class' in nextProps || 'className' in nextProps || 'class' in previousProps || 'className' in previousProps) {
            setClassName(elm, nextProps.class ?? nextProps.className ?? '');
        }

        if ('id' in nextProps || 'id' in previousProps) {
            if (nextProps.id == null || nextProps.id === false) {
                elm.removeAttribute('id');
            } else {
                elm.id = String(nextProps.id);
            }
        }

        if ('text' in nextProps || 'text' in previousProps) {
            if (nextProps.text != null) {
                elm.textContent = String(nextProps.text);
            } else if (!('children' in nextProps) && !('html' in nextProps)) {
                elm.textContent = '';
            }
        }

        if ('html' in nextProps || 'html' in previousProps) {
            if (nextProps.html != null) {
                elm.innerHTML = safeHtml(nextProps.html);
            } else if (!('children' in nextProps) && !('text' in nextProps)) {
                elm.innerHTML = '';
            }
        }

        setAttributes(elm, nextProps.attrs || {}, previousProps.attrs || {});
        setDataAttributes(elm, nextProps.data || {}, previousProps.data || {});
        setStyles(elm, nextProps.style || {}, previousProps.style || {});
        setDelegatedListeners(elm, nextProps.on || {}, previousProps.on || {});

        if (nextProps.ref && typeof nextProps.ref === 'function') {
            nextProps.ref(elm);
        }
    }

    function mountChild(parent, child, anchor = null, context = {}) {
        if (child == null || child === false || child === true) {
            return null;
        }

        if (isNode(child)) {
            parent.insertBefore(child, anchor);
            runtime.metrics.mutationCount += 1;
            return child;
        }

        const vnode = normalizeVNode(child);
        return mountVNode(parent, vnode, anchor, context);
    }

    function mountChildren(parent, children, context = {}) {
        const mounted = [];
        for (const child of children) {
            const node = mountChild(parent, child, null, context);
            if (node) {
                mounted.push(node);
            }
        }
        return mounted;
    }

    function mountVNode(parent, vnode, anchor = null, context = {}) {
        if (vnode == null) {
            return null;
        }

        if (vnode.type === '#node') {
            vnode.el = vnode.node;
            if (anchor !== vnode.node) {
                parent.insertBefore(vnode.node, anchor);
                runtime.metrics.mutationCount += 1;
            }
            return vnode.node;
        }

        if (vnode.type === '#text') {
            const textNode = document.createTextNode(vnode.text);
            vnode.el = textNode;
            parent.insertBefore(textNode, anchor);
            runtime.metrics.mutationCount += 1;
            return textNode;
        }

        if (vnode.type === FRAGMENT) {
            const start = document.createComment('wb-fragment-start');
            const end = document.createComment('wb-fragment-end');
            vnode.el = start;
            vnode.end = end;
            parent.insertBefore(start, anchor);
            parent.insertBefore(end, anchor);
            runtime.metrics.mutationCount += 2;
            const fragmentContext = { ...context };
            for (const child of vnode.children) {
                mountChild(parent, child, end, fragmentContext);
            }
            return start;
        }

        if (vnode.type === CONTEXT_PROVIDER) {
            const start = document.createComment('wb-context-start');
            const end = document.createComment('wb-context-end');
            vnode.el = start;
            vnode.end = end;
            parent.insertBefore(start, anchor);
            parent.insertBefore(end, anchor);
            runtime.metrics.mutationCount += 2;

            const providerContexts = new Map(context?.contexts || []);
            providerContexts.set(vnode.props.context.id, vnode.props.value);

            runtime.contextStack.push(providerContexts);
            try {
                for (const child of vnode.children || []) {
                    mountChild(parent, child, end, { contexts: providerContexts });
                }
            } finally {
                runtime.contextStack.pop();
            }

            return start;
        }

        if (vnode.type === PORTAL) {
            const target = vnode.props.target;
            if (!(target instanceof Element)) {
                throw new Error('Portal target must be an Element');
            }
            vnode.el = document.createComment('wb-portal');
            parent.insertBefore(vnode.el, anchor);
            runtime.metrics.mutationCount += 1;
            clearChildren(target);
            mountChildren(target, vnode.children, context);
            return vnode.el;
        }

        if (typeof vnode.type === 'function') {
            return mountComponent(parent, vnode, anchor, context);
        }

        const element = document.createElement(vnode.type);
        vnode.el = element;
        applyElementProps(element, vnode.props, {});

        if (vnode.props.text == null && vnode.props.html == null) {
            mountChildren(element, vnode.children, context);
        }

        parent.insertBefore(element, anchor);
        runtime.metrics.mutationCount += 1;
        return element;
    }

    function mountComponent(parent, vnode, anchor, context) {
        const scope = createComponentScope(vnode);
        vnode.scope = scope;
        scope.contexts = new Map(context?.contexts || []);

        runtime.componentStack.push(scope);
        runtime.contextStack.push(scope.contexts);
        try {
            const rendered = normalizeVNode(vnode.type({ ...(vnode.props || {}), children: vnode.children }, createComponentApi(scope)));
            scope.subtree = rendered;
            vnode.subtree = rendered;
            const node = mountVNode(parent, rendered, anchor, { contexts: scope.contexts });
            vnode.el = node;
            scope.el = node;
        } catch (error) {
            handleRuntimeError(error);
            throw error;
        } finally {
            runtime.contextStack.pop();
            runtime.componentStack.pop();
        }

        queueLayout(() => {
            for (const mount of scope.mounts) {
                try {
                    mount();
                } catch (error) {
                    handleRuntimeError(error);
                }
            }
        });

        return vnode.el;
    }

    function createComponentApi(scope) {
        return {
            effect,
            computed,
            createSignal,
            createStore,
            onMount,
            onUnmount,
            onCleanup,
            useContext,
            scheduleDOMMutation,
            queueLayout,
            queueEffect,
            yieldToMainThread,
            createPortal,
            createContext,
            renderToString,
            hydrate,
            scope,
        };
    }

    function patchVNode(parent, previousVNode, nextVNode, anchor = null, context = {}) {
        if (!previousVNode) {
            return mountVNode(parent, nextVNode, anchor, context);
        }

        if (!nextVNode) {
            disposeVNode(previousVNode);
            const node = getNodeForVNode(previousVNode);
            if (node && node.parentNode === parent) {
                parent.removeChild(node);
                runtime.metrics.mutationCount += 1;
            }
            return null;
        }

        if (!sameVNodeType(previousVNode, nextVNode)) {
            const newNode = mountVNode(parent, nextVNode, previousVNode.el || anchor, context);
            const oldNode = getNodeForVNode(previousVNode);
            if (oldNode && newNode && oldNode !== newNode && oldNode.parentNode === parent) {
                parent.replaceChild(newNode, oldNode);
                runtime.metrics.mutationCount += 1;
            }
            disposeVNode(previousVNode);
            return newNode;
        }

        nextVNode.el = previousVNode.el;
        nextVNode.end = previousVNode.end;
        nextVNode.scope = previousVNode.scope;

        if (nextVNode.type === '#text') {
            if (previousVNode.text !== nextVNode.text && previousVNode.el) {
                previousVNode.el.nodeValue = nextVNode.text;
                runtime.metrics.mutationCount += 1;
            }
            return previousVNode.el;
        }

        if (nextVNode.type === '#node') {
            return previousVNode.el;
        }

        if (nextVNode.type === FRAGMENT) {
            patchFragment(parent, previousVNode, nextVNode, context);
            return nextVNode.el;
        }

        if (nextVNode.type === CONTEXT_PROVIDER) {
            patchContextProvider(parent, previousVNode, nextVNode, context);
            return nextVNode.el;
        }

        if (nextVNode.type === PORTAL) {
            patchPortal(parent, previousVNode, nextVNode, context);
            return nextVNode.el;
        }

        if (typeof nextVNode.type === 'function') {
            return patchComponent(parent, previousVNode, nextVNode, anchor, context);
        }

        patchElement(previousVNode, nextVNode, context);
        return nextVNode.el;
    }

    function patchElement(previousVNode, nextVNode, context) {
        const element = previousVNode.el;
        const previousProps = previousVNode.props || {};
        const nextProps = nextVNode.props || {};

        applyElementProps(element, nextProps, previousProps);

        if (nextProps.text != null) {
            if (element.textContent !== String(nextProps.text)) {
                element.textContent = String(nextProps.text);
                runtime.metrics.mutationCount += 1;
            }
            return;
        }

        if (nextProps.html != null) {
            const html = String(nextProps.html ?? '');
            const sanitized = safeHtml(html);
            if (element.innerHTML !== String(sanitized)) {
                element.innerHTML = sanitized;
                runtime.metrics.mutationCount += 1;
            }
            return;
        }

        patchChildren(element, previousVNode.children || [], nextVNode.children || [], context);
    }

    function patchChildren(parent, previousChildren, nextChildren, context) {
        const previousByKey = new Map();
        const previousByIndex = previousChildren.slice();
        const used = new Set();

        previousChildren.forEach((child, index) => {
            if (child && child.key != null) {
                previousByKey.set(child.key, { child, index });
            }
        });

        const nextMounted = [];

        for (let index = 0; index < nextChildren.length; index++) {
            const nextChild = normalizeVNode(nextChildren[index]);
            let previousChild = null;

            if (nextChild && nextChild.key != null && previousByKey.has(nextChild.key)) {
                previousChild = previousByKey.get(nextChild.key).child;
                used.add(previousChild);
            } else if (previousByIndex[index] && previousByIndex[index].key == null && nextChild.key == null) {
                previousChild = previousByIndex[index];
                used.add(previousChild);
            }

            if (previousChild) {
                nextMounted.push(patchVNode(parent, previousChild, nextChild, null, context));
            } else {
                nextMounted.push(mountVNode(parent, nextChild, null, context));
            }
        }

        for (const previousChild of previousChildren) {
            if (!used.has(previousChild)) {
                disposeVNode(previousChild);
                const node = getNodeForVNode(previousChild);
                if (node && node.parentNode === parent) {
                    parent.removeChild(node);
                    runtime.metrics.mutationCount += 1;
                }
            }
        }

        let cursor = parent.firstChild;
        for (const node of nextMounted) {
            if (!node) {
                continue;
            }

            if (node !== cursor) {
                parent.insertBefore(node, cursor);
                runtime.metrics.reflowCount += 1;
            }

            cursor = node.nextSibling;
        }

        return nextChildren;
    }

    function patchFragment(parent, previousVNode, nextVNode, context) {
        const start = previousVNode.el;
        const end = previousVNode.end;
        const anchor = end;

        const fragmentChildren = nextVNode.children || [];
        const existingChildren = previousVNode.children || [];
        const fragmentParent = {
            firstChild: start ? start.nextSibling : null,
            insertBefore(node, before) {
                parent.insertBefore(node, before);
            },
            removeChild(node) {
                parent.removeChild(node);
            },
        };

        patchChildren(fragmentParent, existingChildren, fragmentChildren, context);
        nextVNode.children = fragmentChildren;
        nextVNode.el = start;
        nextVNode.end = end;

        if (end && end.parentNode !== parent) {
            parent.insertBefore(end, anchor);
        }
    }

    function patchPortal(parent, previousVNode, nextVNode, context) {
        const target = nextVNode.props.target;
        if (!(target instanceof Element)) {
            throw new Error('Portal target must be an Element');
        }

        clearChildren(target);
        mountChildren(target, nextVNode.children || [], context);
        nextVNode.el = previousVNode.el;
    }

    function patchContextProvider(parent, previousVNode, nextVNode, context) {
        const start = previousVNode.el;
        const end = previousVNode.end;
        const providerContexts = new Map(context?.contexts || []);
        providerContexts.set(nextVNode.props.context.id, nextVNode.props.value);

        nextVNode.el = start;
        nextVNode.end = end;

        const fragmentParent = {
            firstChild: start ? start.nextSibling : null,
            insertBefore(node, before) {
                parent.insertBefore(node, before);
            },
            removeChild(node) {
                parent.removeChild(node);
            },
        };

        runtime.contextStack.push(providerContexts);
        try {
            patchChildren(fragmentParent, previousVNode.children || [], nextVNode.children || [], { contexts: providerContexts });
        } finally {
            runtime.contextStack.pop();
        }
    }

    function patchComponent(parent, previousVNode, nextVNode, anchor, context) {
        const scope = previousVNode.scope || createComponentScope(previousVNode);
        nextVNode.scope = scope;
        scope.vnode = nextVNode;
        scope.contexts = new Map(context?.contexts || []);

        runtime.componentStack.push(scope);
        runtime.contextStack.push(scope.contexts);
        try {
            const rendered = normalizeVNode(nextVNode.type({ ...(nextVNode.props || {}), children: nextVNode.children }, createComponentApi(scope)));
            nextVNode.subtree = rendered;
            const patchedNode = patchVNode(parent, previousVNode.subtree, rendered, anchor, { contexts: scope.contexts });
            nextVNode.el = patchedNode;
            scope.subtree = rendered;
            scope.el = patchedNode;
        } finally {
            runtime.contextStack.pop();
            runtime.componentStack.pop();
        }

        return nextVNode.el;
    }

    function render(vnode, container, options = {}) {
        if (!(container instanceof Element || container instanceof DocumentFragment)) {
            throw new Error('render() requires a container Element or DocumentFragment');
        }

        const normalized = normalizeVNode(vnode);
        const priority = options.priority || 'normal';

        return scheduleDOMMutation(() => {
            const state = runtime.roots.get(container) || { vnode: null };

            if (!state.vnode) {
                clearChildren(container);
                const node = mountVNode(container, normalized, null, { contexts: new Map() });
                state.vnode = normalized;
                state.node = node;
                runtime.roots.set(container, state);
                return normalized;
            }

            const nextVNode = normalized;
            patchVNode(container, state.vnode, nextVNode, null, { contexts: new Map() });
            state.vnode = nextVNode;
            state.node = getNodeForVNode(nextVNode);
            runtime.roots.set(container, state);
            return nextVNode;
        }, priority);
    }

    function hydrate(existingDOM, vnode) {
        if (!(existingDOM instanceof Element)) {
            throw new Error('hydrate() requires an existing root Element');
        }

        const root = existingDOM;
        return scheduleDOMMutation(() => {
            const normalized = normalizeVNode(vnode);
            const state = runtime.roots.get(root) || { vnode: null };

            if (!state.vnode) {
                runtime.roots.set(root, state);
                clearChildren(root);
                const node = mountVNode(root, normalized, null, { contexts: new Map() });
                state.vnode = normalized;
                state.node = node;
                return normalized;
            }

            patchVNode(root, state.vnode, normalized, null, { contexts: new Map() });
            state.vnode = normalized;
            runtime.roots.set(root, state);
            return normalized;
        });
    }

    function renderToString(vnode) {
        const node = normalizeVNode(vnode);

        if (node.type === '#node') {
            return node.el?.outerHTML || '';
        }

        if (node.type === '#text') {
            return escapeHtml(node.text);
        }

        if (node.type === FRAGMENT) {
            return (node.children || []).map(renderToString).join('');
        }

        if (node.type === PORTAL) {
            return (node.children || []).map(renderToString).join('');
        }

        if (typeof node.type === 'function') {
            const rendered = node.type({ ...(node.props || {}), children: node.children }, createComponentApi(createComponentScope(node)));
            return renderToString(rendered);
        }

        const attrs = [];
        const props = node.props || {};

        if (props.id) attrs.push(`id="${escapeHtml(props.id)}"`);
        if (props.class || props.className) attrs.push(`class="${escapeHtml(props.class ?? props.className)}"`);

        if (props.attrs) {
            for (const [key, value] of Object.entries(props.attrs)) {
                if (value === false || value == null) {
                    continue;
                }
                if (value === true) {
                    attrs.push(`${key}`);
                } else {
                    attrs.push(`${key}="${escapeHtml(value)}"`);
                }
            }
        }

        if (props.data) {
            for (const [key, value] of Object.entries(props.data)) {
                if (value != null) {
                    attrs.push(`data-${key}="${escapeHtml(value)}"`);
                }
            }
        }

        if (props.style) {
            const css = Object.entries(props.style)
                .filter(([, value]) => value != null)
                .map(([key, value]) => `${key}:${value}`)
                .join(';');
            if (css) {
                attrs.push(`style="${escapeHtml(css)}"`);
            }
        }

        if (props.text != null) {
            return `<${node.type}${attrs.length ? ' ' + attrs.join(' ') : ''}>${escapeHtml(props.text)}</${node.type}>`;
        }

        if (props.html != null) {
            return `<${node.type}${attrs.length ? ' ' + attrs.join(' ') : ''}>${sanitizeHtml(props.html)}</${node.type}>`;
        }

        const children = (node.children || []).map(renderToString).join('');
        return `<${node.type}${attrs.length ? ' ' + attrs.join(' ') : ''}>${children}</${node.type}>`;
    }

    function serializeTree(value) {
        if (isNode(value)) {
            return value.outerHTML ?? value.textContent ?? '';
        }

        return renderToString(value);
    }

    function diffNodes(previousTree, nextTree, path = '0') {
        const previous = normalizeVNode(previousTree);
        const next = normalizeVNode(nextTree);
        const patches = [];

        if (!previous && next) {
            patches.push({ type: 'insert', path, node: next });
            return patches;
        }

        if (previous && !next) {
            patches.push({ type: 'remove', path, node: previous });
            return patches;
        }

        if (previous.type !== next.type || previous.key !== next.key) {
            patches.push({ type: 'replace', path, previous, next });
            return patches;
        }

        if (previous.type === '#text' && previous.text !== next.text) {
            patches.push({ type: 'text', path, value: next.text });
        }

        const previousChildren = previous.children || [];
        const nextChildren = next.children || [];
        const maxLength = Math.max(previousChildren.length, nextChildren.length);

        for (let index = 0; index < maxLength; index++) {
            patches.push(...diffNodes(previousChildren[index], nextChildren[index], `${path}.${index}`));
        }

        return patches;
    }

    function createPortal(children, target) {
        return {
            __wbVNode: true,
            type: PORTAL,
            key: null,
            props: { target },
            children: normalizeChildrenInput(children),
            el: null,
            ownerId: null,
        };
    }

    function compileTemplate(templateString) {
        const template = document.createElement('template');
        template.innerHTML = sanitizeHtml(templateString);

        return function compiledTemplate(props = {}) {
            const root = template.content.cloneNode(true);
            const fragmentNode = createFragmentVNode([]);
            fragmentNode.el = root.firstChild || null;
            return fragmentNode;
        };
    }

    function preserveStateOnReload() {
        runtime.preserveStateOnReloadFlag = true;
        return runtime.preserveStateOnReloadFlag;
    }

    function registerRuntimePlugin(plugin) {
        if (!plugin || typeof plugin !== 'object') {
            throw new Error('registerRuntimePlugin() requires a plugin object');
        }

        runtime.plugins.add(plugin);
        return () => runtime.plugins.delete(plugin);
    }

    function onRenderStart(fn) {
        runtime.renderHooks.start.add(fn);
        return () => runtime.renderHooks.start.delete(fn);
    }

    function onCommit(fn) {
        runtime.renderHooks.commit.add(fn);
        return () => runtime.renderHooks.commit.delete(fn);
    }

    function onRenderError(fn) {
        runtime.renderHooks.error.add(fn);
        return () => runtime.renderHooks.error.delete(fn);
    }

    function assertManagedNode(node) {
        if (!isNode(node)) {
            throw new Error('Managed node assertion failed: expected DOM Node');
        }
        return node;
    }

    function trackDetachedNodes() {
        return runtime.metrics.detachedNodes;
    }

    function yieldToMainThread() {
        return new Promise((resolve) => {
            if (typeof window.requestAnimationFrame === 'function') {
                window.requestAnimationFrame(() => resolve());
            } else {
                setTimeout(resolve, 0);
            }
        });
    }

    function createErrorBoundary(fallback) {
        return function ErrorBoundary(props = {}) {
            try {
                return typeof props.children === 'function' ? props.children() : (props.children ?? null);
            } catch (error) {
                return typeof fallback === 'function' ? fallback(error) : fallback;
            }
        };
    }

    function makeDomElement(tag, options = {}) {
        const element = document.createElement(tag);

        if (options.class) {
            const classes = String(options.class).split(/\s+/).filter(Boolean);
            if (classes.length) {
                element.classList.add(...classes);
            }
        }

        if (options.id) {
            element.id = options.id;
        }

        if (options.text != null) {
            element.textContent = String(options.text);
        }

        if (options.html != null) {
            element.innerHTML = safeHtml(options.html);
        }

        if (options.attrs) {
            setAttributes(element, options.attrs, {});
        }

        if (options.data) {
            setDataAttributes(element, options.data, {});
        }

        if (options.style) {
            setStyles(element, options.style, {});
        }

        if (options.children) {
            for (const child of options.children) {
                if (isNode(child)) {
                    element.appendChild(child);
                } else if (child != null) {
                    element.appendChild(document.createTextNode(String(child)));
                }
            }
        }

        if (options.on) {
            for (const [event, handler] of Object.entries(options.on)) {
                registerDelegatedHandler(element, event, handler);
            }
        }

        return element;
    }

    function getRuntimeSnapshot() {
        return {
            metrics: { ...runtime.metrics },
            renderQueue: runtime.renderQueue.length,
            layoutQueue: runtime.layoutQueue.length,
            effectQueue: runtime.effectQueue.length,
            plugins: runtime.plugins.size,
            detachedNodes: runtime.metrics.detachedNodes,
            preserveStateOnReload: runtime.preserveStateOnReloadFlag,
        };
    }

    function createRuntimeFacade() {
        return {
            FRAGMENT,
            PORTAL,
            CONTEXT_PROVIDER,
            h,
            createSignal,
            createStore,
            computed,
            effect,
            track,
            trigger,
            onMount,
            onUnmount,
            onCleanup,
            createContext,
            useContext,
            scheduleDOMMutation,
            queueLayout,
            queueEffect,
            renderQueue: runtime.renderQueue,
            commitPhase: flushScheduler,
            layoutPhase: () => flushPhase(runtime.layoutQueue),
            effectPhase: () => flushPhase(runtime.effectQueue),
            diffNodes,
            render,
            hydrate,
            renderToString,
            serializeTree,
            createPortal,
            compileTemplate,
            createErrorBoundary,
            preserveStateOnReload,
            registerRuntimePlugin,
            onRenderStart,
            onCommit,
            onRenderError,
            yieldToMainThread,
            assertManagedNode,
            trackDetachedNodes,
            disposeTimers,
            disposeObservers,
            disposeListeners,
            registerNodeCleanup,
            registerDelegatedHandler,
            getRuntimeSnapshot,
            metrics: runtime.metrics,
        };
    }

    const runtimeFacade = createRuntimeFacade();

    function el(tag, options = {}) {
        return makeDomElement(tag, options);
    }

    window.WBDom = {
        ...runtimeFacade,
        el,
        escapeHtml,
        hashId,
        clearChildren,
        replaceContent,
        fragment,
        safeHtml,
    };

    window.WB = window.WB || {};
    window.WB.dom = window.WBDom;
    window.WB.domRuntime = window.WBDom;

    window.__WB_DEVTOOLS__ = window.__WB_DEVTOOLS__ || {};
    window.__WB_DEVTOOLS__.dom = window.WBDom;

    window.el = el;
})();
