'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./autofillscopeguard.js');

const evaluate = mod.evaluateAutofillScopeGuard;
const describe = mod.describeAutofillScopeGuard;

test('autofillscopeguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('autofillscopeguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('autofillscopeguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('autofillscopeguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": true,
  "categories": [
    "address",
    "creditcard"
  ],
  "crossSite": false,
  "maxCategories": 4
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('autofillscopeguard flags AUTOFILL_CATEGORY_UNKNOWN', () => {
  const snapshot = {
  "categories": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.AUTOFILL_CATEGORY_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('autofillscopeguard flags AUTOFILL_CROSS_SITE', () => {
  const snapshot = {
  "crossSite": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.AUTOFILL_CROSS_SITE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('autofillscopeguard flags AUTOFILL_CATEGORY_LIMIT', () => {
  const snapshot = {
  "categories": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.AUTOFILL_CATEGORY_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('autofillscopeguard flags AUTOFILL_CATEGORY_EMPTY', () => {
  const snapshot = {
  "categories": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.AUTOFILL_CATEGORY_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('autofillscopeguard describe renders findings in order', () => {
  const snapshot = {"categories": ["zzz-unknown"]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('autofillscopeguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
