//
// tools/ui-lint/lib/design-tokens/resolver/evaluate-units.mjs
// Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
//

import { resolveVarChain } from './resolve-var-chain.mjs';

function splitTopLevelArguments(text) {
    const parts = [];
    let current = '';
    let depth = 0;

    for (const character of text) {
        if (character === '(') depth += 1;
        if (character === ')') depth -= 1;
        if (character === ',' && depth === 0) {
            parts.push(current.trim());
            current = '';
            continue;
        }
        current += character;
    }

    if (current.trim()) parts.push(current.trim());
    return parts;
}

function toNumberWithUnit(value, context = {}) {
    const text = String(value || '').trim();
    const number = Number.parseFloat(text);
    if (Number.isNaN(number)) return 0;

    if (text.endsWith('px')) return number;
    if (text.endsWith('rem') || text.endsWith('em')) return number * (context.rootFontSize || 16);
    if (text.endsWith('ms')) return number;
    if (text.endsWith('s')) return number * 1000;
    if (text.endsWith('vw')) return (context.viewportWidth || 0) * number / 100;
    if (text.endsWith('vh')) return (context.viewportHeight || 0) * number / 100;
    if (text.endsWith('%')) return (context.percentBase || 100) * number / 100;
    return number;
}

function normalizeMathExpression(expression, context = {}) {
    return String(expression)
        .replace(/(-?\d*\.?\d+)(px|rem|em|ms|s|vw|vh|%)/g, (_, numericValue, unit) => {
            const converted = toNumberWithUnit(`${numericValue}${unit}`, context);
            return String(converted);
        })
        .replace(/\s+/g, ' ')
        .trim();
}

function evaluateArithmetic(expression) {
    if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        return NaN;
    }

    // Safe because the expression is reduced to numbers and arithmetic operators only.
    return Function(`"use strict"; return (${expression});`)();
}

function evaluateFunctionCall(value, context) {
    const text = String(value || '').trim();
    if (text.startsWith('clamp(') && text.endsWith(')')) {
        const [minValue, preferredValue, maxValue] = splitTopLevelArguments(text.slice(6, -1));
        const minimum = evaluateDimension(minValue, context);
        const preferred = evaluateDimension(preferredValue, context);
        const maximum = evaluateDimension(maxValue, context);
        return Math.min(maximum, Math.max(minimum, preferred));
    }

    if (text.startsWith('min(') && text.endsWith(')')) {
        return Math.min(...splitTopLevelArguments(text.slice(4, -1)).map((entry) => evaluateDimension(entry, context)));
    }

    if (text.startsWith('max(') && text.endsWith(')')) {
        return Math.max(...splitTopLevelArguments(text.slice(4, -1)).map((entry) => evaluateDimension(entry, context)));
    }

    if (text.startsWith('calc(') && text.endsWith(')')) {
        const normalizedExpression = normalizeMathExpression(text.slice(5, -1), context);
        return evaluateArithmetic(normalizedExpression);
    }

    return NaN;
}

export function evaluateDimension(value, context = {}) {
    if (typeof value === 'number') return value;
    if (value == null) return 0;

    const resolved = resolveVarChain(String(value), context.resolveToken || (() => ({ value: '' })), context);
    const text = resolved.value.trim();
    if (!text) return 0;

    const functionalValue = evaluateFunctionCall(text, context);
    if (!Number.isNaN(functionalValue)) return functionalValue;

    if (/^-?\d*\.?\d+(px|rem|em|ms|s|vw|vh|%)?$/.test(text)) {
        return toNumberWithUnit(text, context);
    }

    const fallbackExpression = normalizeMathExpression(text, context);
    const evaluated = evaluateArithmetic(fallbackExpression);
    return Number.isNaN(evaluated) ? 0 : evaluated;
}

export function evaluateDuration(value, context = {}) {
    return evaluateDimension(value, context);
}