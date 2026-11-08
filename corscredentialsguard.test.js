'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./corscredentialsguard.js');

const REASONS = ["CORSCRED_FLAG_OFF", "CORSCRED_REPORT_ONLY", "CORSCRED_MODE_INVALID", "CORSCRED_COUNT_OUT_OF_RANGE", "CORSCRED_ENDPOINT_INSECURE", "CORSCRED_ENDPOINT_TOO_LONG", "CORSCRED_NOTE_CONTROL", "CORSCRED_PATH_TRAVERSAL", "CORSCRED_ITEM_UNKNOWN", "CORSCRED_ITEM_DUPLICATE", "CORSCRED_ITEM_COUNT", "CORSCRED_BASELINE_EMPTY"];
const CLEAN = {
  "corsCred": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 1200,
    "endpoint": "https://creds.example.com/allow",
    "note": "cred-note",
    "storagePath": "policies/creds",
    "items": [
      "https://app.example.com"
    ],
    "baseline": [
      "creds"
    ]
  }
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function withValue(path, value) {
  const snapshot = clone(CLEAN);
  const parts = path.split('.');
  let cursor = snapshot;
  for (const part of parts.slice(0, -1)) {
    if (typeof cursor[part] !== 'object' || cursor[part] === null) {
      cursor[part] = {};
    }
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
  return snapshot;
}

function hasKey(result, key) {
  return result.findings.some((finding) => finding.key === key);
}

test('reason table covers every rule', () => {
  assert.deepStrictEqual(guard.RULES.map((rule) => rule.key), REASONS);
});

test('exported evaluator is callable', () => {
  assert.strictEqual(typeof guard.evaluateCorscredentialsGuard, 'function');
  assert.strictEqual(typeof guard.describeCorscredentialsGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCorscredentialsGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCorscredentialsGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CORSCRED_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.enabled', false));
  assert.ok(hasKey(result, 'CORSCRED_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSCRED_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.reportOnly', true));
  assert.ok(hasKey(result, 'CORSCRED_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CORSCRED_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSCRED_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.lifetime', 299));
  assert.ok(hasKey(result, 'CORSCRED_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CORSCRED_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSCRED_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CORSCRED_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CORSCRED_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CORSCRED_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSCRED_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CORSCRED_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSCRED_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CORSCRED_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CORSCRED_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSCRED_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.baseline', []));
  assert.ok(hasKey(result, 'CORSCRED_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CORSCRED_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCorscredentialsGuard(withValue('corsCred.enabled', false));
  const text = guard.describeCorscredentialsGuard(result);
  assert.ok(text.includes('CORSCRED_FLAG_OFF'));
  assert.ok(text.length > 'corscredentialsguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCorscredentialsGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCorscredentialsGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
