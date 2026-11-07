'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionnotificationguard.js');

const REASONS = ["PERMNOT_FLAG_OFF", "PERMNOT_REPORT_ONLY", "PERMNOT_MODE_INVALID", "PERMNOT_COUNT_OUT_OF_RANGE", "PERMNOT_ENDPOINT_INSECURE", "PERMNOT_ENDPOINT_TOO_LONG", "PERMNOT_NOTE_CONTROL", "PERMNOT_PATH_TRAVERSAL", "PERMNOT_ITEM_UNKNOWN", "PERMNOT_ITEM_DUPLICATE", "PERMNOT_ITEM_COUNT", "PERMNOT_BASELINE_EMPTY"];
const CLEAN = {
  "permNotify": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 360,
    "endpoint": "https://notify.example.com/policy",
    "note": "notify-note",
    "storagePath": "policies/notify",
    "items": [
      "notifications=()"
    ],
    "baseline": [
      "notify"
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
  assert.strictEqual(typeof guard.evaluatePermissionnotificationGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionnotificationGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionnotificationGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionnotificationGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMNOT_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.enabled', false));
  assert.ok(hasKey(result, 'PERMNOT_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMNOT_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.reportOnly', true));
  assert.ok(hasKey(result, 'PERMNOT_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMNOT_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMNOT_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.lifetime', 89));
  assert.ok(hasKey(result, 'PERMNOT_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMNOT_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMNOT_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMNOT_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMNOT_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMNOT_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMNOT_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMNOT_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMNOT_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMNOT_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMNOT_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMNOT_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.baseline', []));
  assert.ok(hasKey(result, 'PERMNOT_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMNOT_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionnotificationGuard(withValue('permNotify.enabled', false));
  const text = guard.describePermissionnotificationGuard(result);
  assert.ok(text.includes('PERMNOT_FLAG_OFF'));
  assert.ok(text.length > 'permissionnotificationguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionnotificationGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionnotificationGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
