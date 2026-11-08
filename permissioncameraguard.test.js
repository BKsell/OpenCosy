'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissioncameraguard.js');

const REASONS = ["PERMCAM_FLAG_OFF", "PERMCAM_REPORT_ONLY", "PERMCAM_MODE_INVALID", "PERMCAM_COUNT_OUT_OF_RANGE", "PERMCAM_ENDPOINT_INSECURE", "PERMCAM_ENDPOINT_TOO_LONG", "PERMCAM_NOTE_CONTROL", "PERMCAM_PATH_TRAVERSAL", "PERMCAM_ITEM_UNKNOWN", "PERMCAM_ITEM_DUPLICATE", "PERMCAM_ITEM_COUNT", "PERMCAM_BASELINE_EMPTY"];
const CLEAN = {
  "permCam": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 480,
    "endpoint": "https://cam.example.com/policy",
    "note": "cam-note",
    "storagePath": "policies/cam",
    "items": [
      "camera=()"
    ],
    "baseline": [
      "cam"
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
  assert.strictEqual(typeof guard.evaluatePermissioncameraGuard, 'function');
  assert.strictEqual(typeof guard.describePermissioncameraGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissioncameraGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissioncameraGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMCAM_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.enabled', false));
  assert.ok(hasKey(result, 'PERMCAM_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCAM_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.reportOnly', true));
  assert.ok(hasKey(result, 'PERMCAM_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMCAM_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCAM_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.lifetime', 119));
  assert.ok(hasKey(result, 'PERMCAM_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMCAM_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCAM_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMCAM_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMCAM_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMCAM_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCAM_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMCAM_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCAM_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMCAM_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMCAM_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCAM_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.baseline', []));
  assert.ok(hasKey(result, 'PERMCAM_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMCAM_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissioncameraGuard(withValue('permCam.enabled', false));
  const text = guard.describePermissioncameraGuard(result);
  assert.ok(text.includes('PERMCAM_FLAG_OFF'));
  assert.ok(text.length > 'permissioncameraguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissioncameraGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissioncameraGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
