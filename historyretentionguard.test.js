'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./historyretentionguard.js');

const evaluate = mod.evaluateHistoryRetentionGuard;
const describe = mod.describeHistoryRetentionGuard;

test('historyretentionguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('historyretentionguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('historyretentionguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('historyretentionguard clean snapshot produces no findings', () => {
  const clean = {
  "retentionDays": 90,
  "incognitoPersist": false,
  "maxEntries": 100000
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('historyretentionguard flags HISTORY_DAYS_RANGE', () => {
  const snapshot = {
  "retentionDays": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HISTORY_DAYS_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('historyretentionguard flags HISTORY_INCOGNITO_PERSIST', () => {
  const snapshot = {
  "incognitoPersist": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HISTORY_INCOGNITO_PERSIST);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('historyretentionguard flags HISTORY_ENTRY_LIMIT', () => {
  const snapshot = {
  "maxEntries": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HISTORY_ENTRY_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('historyretentionguard describe renders findings in order', () => {
  const snapshot = {"retentionDays": 0};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('historyretentionguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
