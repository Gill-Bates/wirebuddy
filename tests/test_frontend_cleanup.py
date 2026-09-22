#
# tests/test_frontend_cleanup.py
# Copyright (C) 2026 Gill-Bates http://github.com/Gill-Bates
# SPDX-License-Identifier: MIT
#
"""Regression coverage for the retained Settings frontend helpers."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_active_retention_helpers_and_template_wiring() -> None:
	"""Lock the retention slider mapping while removing obsolete settings code."""
	node = shutil.which("node")
	if node is None:
		pytest.skip("Node.js is required for frontend helper characterization")
	node_script = r"""
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync('app/static/js/settings.js', 'utf8');
const template = fs.readFileSync('app/templates/settings/_tab_logs.html', 'utf8');

function extract(name) {
    const marker = `function ${name}(`;
    const start = source.indexOf(marker);
    if (start < 0) throw new Error(`missing ${name}`);
    const bodyStart = source.indexOf('{', start);
    let depth = 0;
    for (let i = bodyStart; i < source.length; i += 1) {
        if (source[i] === '{') depth += 1;
        if (source[i] === '}' && --depth === 0) return source.slice(start, i + 1);
    }
    throw new Error(`unterminated ${name}`);
}

const helpers = [
    source.match(/const TSDB_RETENTION_VALUES = \[[^;]+;/)[0],
    source.match(/const DNS_METRICS_RETENTION_VALUES = \[[^;]+;/)[0],
    extract('tsdbRetentionLabel'),
    extract('tsdbRetentionIndexForDays'),
    extract('tsdbRetentionDaysFromSlider'),
    extract('updateTsdbRetentionPreview'),
    extract('dnsMetricsRetentionLabel'),
    extract('dnsMetricsRetentionIndexForDays'),
    extract('dnsMetricsRetentionDaysFromSlider'),
    extract('updateDnsMetricsRetentionPreview'),
].join('\n');

const labels = new Map();
const document = { getElementById(id) {
    if (!labels.has(id)) labels.set(id, { textContent: '', className: '' });
    return labels.get(id);
} };
const context = { document };
vm.runInNewContext(`${helpers}\nthis.api = {
    tsdbRetentionLabel, tsdbRetentionIndexForDays, tsdbRetentionDaysFromSlider,
    updateTsdbRetentionPreview, dnsMetricsRetentionLabel,
    dnsMetricsRetentionIndexForDays, dnsMetricsRetentionDaysFromSlider,
    updateDnsMetricsRetentionPreview,
};`, context);
const api = context.api;
for (const prefix of ['tsdb', 'dnsMetrics']) {
    const label = api[`${prefix}RetentionLabel`];
    const index = api[`${prefix}RetentionIndexForDays`];
    const days = api[`${prefix}RetentionDaysFromSlider`];
    const preview = api[`update${prefix[0].toUpperCase()}${prefix.slice(1)}RetentionPreview`];
    if (label(0) !== 'No Logs' || label(365) !== '1 Year' || label(30) !== '30 Days') throw new Error(`${prefix} labels`);
    const defaultIndex = prefix === 'tsdb' ? 5 : 2;
    const defaultDays = prefix === 'tsdb' ? 365 : 30;
    if (index(30) !== 2 || index(999) !== defaultIndex || days(-1) !== 0
        || days(99) !== 365 || days('bad') !== defaultDays) throw new Error(`${prefix} mapping`);
    const valueId = `${prefix === 'tsdb' ? 'tsdb' : 'dns-metrics'}-retention-value`;
    if (preview(0) !== 0 || labels.get(valueId).className !== 'badge text-bg-danger') {
        throw new Error(`${prefix} preview off`);
    }
    if (preview(5) !== 365 || labels.get(valueId).className !== 'badge text-bg-secondary') {
        throw new Error(`${prefix} preview on`);
    }
}

for (const id of ['tsdb-retention-slider', 'dns-metrics-retention-slider']) {
    if (!template.includes(`id="${id}"`)) throw new Error(`missing ${id}`);
}
for (const id of ['tsdb-retention-value', 'dns-metrics-retention-value']) {
    if (!template.includes(`id="${id}"`)) throw new Error(`missing ${id}`);
}
for (const pattern of [
    /updateTsdbRetentionPreview\(this\.value\)/,
    /void applyTsdbRetentionChange\(this\.value\)/,
    /updateDnsMetricsRetentionPreview\(this\.value\)/,
    /void applyDnsMetricsRetentionChange\(this\.value\)/,
]) {
    if (!pattern.test(source)) throw new Error(`missing wiring ${pattern}`);
}
"""
	run = subprocess.run(
		[node],
		input=node_script,
		cwd=ROOT,
		text=True,
		capture_output=True,
		check=False,
		timeout=10,
	)
	assert run.returncode == 0, run.stderr

