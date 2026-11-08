'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./priorityhintguard.js');

const evaluate = mod.evaluatePriorityHintGuard;
const describe = mod.describePriorityHintGuard;

test('priorityhintguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('priorityhintguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('priorityhintguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('priorityhintguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "priority": "u=1, i"
  },
  "resources": [
    "https://cdn.example.com/app.js"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('priorityhintguard flags PRIORITY_INVALID', () => {
  const snapshot = {
  "headers": {
    "priority": "*"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRIORITY_INVALID);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('priorityhintguard flags PRIORITY_NOT_HTTPS', () => {
  const snapshot = {
  "resources": [
    "http://insecure.test/x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRIORITY_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('priorityhintguard flags PRIORITY_DUPLICATE', () => {
  const snapshot = {
  "resources": [
    "dup",
    "dup"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRIORITY_DUPLICATE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('priorityhintguard describe renders findings in order', () => {
  const snapshot = {"headers": {"priority": "*"}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('priorityhintguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
