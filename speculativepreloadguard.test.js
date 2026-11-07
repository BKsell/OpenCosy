'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./speculativepreloadguard.js');

const evaluate = mod.evaluateSpeculativePreloadGuard;
const describe = mod.describeSpeculativePreloadGuard;

test('speculativepreloadguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('speculativepreloadguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('speculativepreloadguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('speculativepreloadguard clean snapshot produces no findings', () => {
  const clean = {
  "url": "https://example.com/page",
  "rules": [
    "https://cdn.example.com/app.js"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('speculativepreloadguard flags PRELOAD_RULES_MISSING', () => {
  const snapshot = {
  "rules": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRELOAD_RULES_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('speculativepreloadguard flags PRELOAD_NOT_HTTPS', () => {
  const snapshot = {
  "rules": [
    "http://insecure.test/x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRELOAD_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('speculativepreloadguard flags PRELOAD_RULE_LIMIT', () => {
  const snapshot = {
  "rules": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4",
    "ok5",
    "ok6",
    "ok7",
    "ok8",
    "ok9",
    "ok10",
    "ok11",
    "ok12"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRELOAD_RULE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('speculativepreloadguard flags PRELOAD_EMPTY_URL', () => {
  const snapshot = {
  "rules": [
    ""
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRELOAD_EMPTY_URL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('speculativepreloadguard describe renders findings in order', () => {
  const snapshot = {"rules": []};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('speculativepreloadguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
