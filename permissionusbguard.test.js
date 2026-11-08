'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionusbguard.js');

const REASONS = ["PERMUSB_FLAG_OFF", "PERMUSB_REPORT_ONLY", "PERMUSB_MODE_INVALID", "PERMUSB_COUNT_OUT_OF_RANGE", "PERMUSB_ENDPOINT_INSECURE", "PERMUSB_ENDPOINT_TOO_LONG", "PERMUSB_NOTE_CONTROL", "PERMUSB_PATH_TRAVERSAL", "PERMUSB_ITEM_UNKNOWN", "PERMUSB_ITEM_DUPLICATE", "PERMUSB_ITEM_COUNT", "PERMUSB_BASELINE_EMPTY"];
const CLEAN = {
  "permUsb": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 300,
    "endpoint": "https://usb.example.com/policy",
    "note": "usb-note",
    "storagePath": "policies/usb",
    "items": [
      "usb=()"
    ],
    "baseline": [
      "usb"
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
  assert.strictEqual(typeof guard.evaluatePermissionusbGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionusbGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionusbGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionusbGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMUSB_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.enabled', false));
  assert.ok(hasKey(result, 'PERMUSB_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMUSB_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.reportOnly', true));
  assert.ok(hasKey(result, 'PERMUSB_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMUSB_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMUSB_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.lifetime', 59));
  assert.ok(hasKey(result, 'PERMUSB_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMUSB_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMUSB_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMUSB_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMUSB_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMUSB_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMUSB_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMUSB_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMUSB_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMUSB_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMUSB_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMUSB_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.baseline', []));
  assert.ok(hasKey(result, 'PERMUSB_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMUSB_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionusbGuard(withValue('permUsb.enabled', false));
  const text = guard.describePermissionusbGuard(result);
  assert.ok(text.includes('PERMUSB_FLAG_OFF'));
  assert.ok(text.length > 'permissionusbguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionusbGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionusbGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
