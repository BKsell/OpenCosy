'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionbluetoothguard.js');

const REASONS = ["PERMBT_FLAG_OFF", "PERMBT_REPORT_ONLY", "PERMBT_MODE_INVALID", "PERMBT_COUNT_OUT_OF_RANGE", "PERMBT_ENDPOINT_INSECURE", "PERMBT_ENDPOINT_TOO_LONG", "PERMBT_NOTE_CONTROL", "PERMBT_PATH_TRAVERSAL", "PERMBT_ITEM_UNKNOWN", "PERMBT_ITEM_DUPLICATE", "PERMBT_ITEM_COUNT", "PERMBT_BASELINE_EMPTY"];
const CLEAN = {
  "permBt": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 300,
    "endpoint": "https://bt.example.com/policy",
    "note": "bt-note",
    "storagePath": "policies/bt",
    "items": [
      "bluetooth=()"
    ],
    "baseline": [
      "bt"
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
  assert.strictEqual(typeof guard.evaluatePermissionbluetoothGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionbluetoothGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionbluetoothGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionbluetoothGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMBT_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.enabled', false));
  assert.ok(hasKey(result, 'PERMBT_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMBT_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.reportOnly', true));
  assert.ok(hasKey(result, 'PERMBT_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMBT_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMBT_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.lifetime', 59));
  assert.ok(hasKey(result, 'PERMBT_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMBT_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMBT_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMBT_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMBT_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMBT_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMBT_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMBT_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMBT_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMBT_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMBT_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMBT_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.baseline', []));
  assert.ok(hasKey(result, 'PERMBT_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMBT_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionbluetoothGuard(withValue('permBt.enabled', false));
  const text = guard.describePermissionbluetoothGuard(result);
  assert.ok(text.includes('PERMBT_FLAG_OFF'));
  assert.ok(text.length > 'permissionbluetoothguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionbluetoothGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionbluetoothGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
