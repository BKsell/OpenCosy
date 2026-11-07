'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./dragdroptrustguard.js');

const evaluate = mod.evaluateDragDropTrustGuard;
const describe = mod.describeDragDropTrustGuard;

test('dragdroptrustguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('dragdroptrustguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('dragdroptrustguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('dragdroptrustguard clean snapshot produces no findings', () => {
  const clean = {
  "types": [
    "text/plain"
  ],
  "externalDrop": false,
  "url": "https://example.com",
  "maxTypes": 4
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('dragdroptrustguard flags DRAG_TYPE_UNKNOWN', () => {
  const snapshot = {
  "types": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DRAG_TYPE_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('dragdroptrustguard flags DRAG_EXTERNAL_RISK', () => {
  const snapshot = {
  "externalDrop": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DRAG_EXTERNAL_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('dragdroptrustguard flags DRAG_TYPE_LIMIT', () => {
  const snapshot = {
  "types": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DRAG_TYPE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('dragdroptrustguard flags DRAG_TYPE_EMPTY', () => {
  const snapshot = {
  "types": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DRAG_TYPE_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('dragdroptrustguard flags DRAG_URL_NOT_HTTPS', () => {
  const snapshot = {
  "url": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DRAG_URL_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('dragdroptrustguard describe renders findings in order', () => {
  const snapshot = {"types": ["zzz-unknown"]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('dragdroptrustguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
