'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./originisolationguard.js');

const evaluate = mod.evaluateOriginIsolationGuard;
const describe = mod.describeOriginIsolationGuard;

test('originisolationguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('originisolationguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('originisolationguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('originisolationguard clean snapshot produces no findings', () => {
  const clean = {
  "coop": "same-origin",
  "coep": "require-corp",
  "url": "https://example.com/app"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('originisolationguard flags ISOLATION_COOP_MISSING', () => {
  const snapshot = {
  "coop": ""
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_COOP_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('originisolationguard flags ISOLATION_COEP_MISSING', () => {
  const snapshot = {
  "coep": ""
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_COEP_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('originisolationguard flags ISOLATION_UNSAFE_COOP', () => {
  const snapshot = {
  "coop": "unsafe-none"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_UNSAFE_COOP);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('originisolationguard flags ISOLATION_UNSAFE_COEP', () => {
  const snapshot = {
  "coep": "unsafe-none"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_UNSAFE_COEP);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('originisolationguard flags ISOLATION_NOT_HTTPS', () => {
  const snapshot = {
  "url": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('originisolationguard flags ISOLATION_MISMATCH', () => {
  const snapshot = {
  "mismatchCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ISOLATION_MISMATCH);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('originisolationguard describe renders findings in order', () => {
  const snapshot = {"coop": ""};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('originisolationguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
