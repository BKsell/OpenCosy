'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionpaymentguard.js');

const REASONS = ["PERMPAY_FLAG_OFF", "PERMPAY_REPORT_ONLY", "PERMPAY_MODE_INVALID", "PERMPAY_COUNT_OUT_OF_RANGE", "PERMPAY_ENDPOINT_INSECURE", "PERMPAY_ENDPOINT_TOO_LONG", "PERMPAY_NOTE_CONTROL", "PERMPAY_PATH_TRAVERSAL", "PERMPAY_ITEM_UNKNOWN", "PERMPAY_ITEM_DUPLICATE", "PERMPAY_ITEM_COUNT", "PERMPAY_BASELINE_EMPTY"];
const CLEAN = {
  "permPay": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 240,
    "endpoint": "https://pay.example.com/policy",
    "note": "pay-note",
    "storagePath": "policies/pay",
    "items": [
      "payment=()"
    ],
    "baseline": [
      "pay"
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
  assert.strictEqual(typeof guard.evaluatePermissionpaymentGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionpaymentGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionpaymentGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionpaymentGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMPAY_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.enabled', false));
  assert.ok(hasKey(result, 'PERMPAY_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMPAY_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.reportOnly', true));
  assert.ok(hasKey(result, 'PERMPAY_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMPAY_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMPAY_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.lifetime', 59));
  assert.ok(hasKey(result, 'PERMPAY_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMPAY_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMPAY_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMPAY_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMPAY_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMPAY_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMPAY_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMPAY_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMPAY_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMPAY_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMPAY_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMPAY_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.baseline', []));
  assert.ok(hasKey(result, 'PERMPAY_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMPAY_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionpaymentGuard(withValue('permPay.enabled', false));
  const text = guard.describePermissionpaymentGuard(result);
  assert.ok(text.includes('PERMPAY_FLAG_OFF'));
  assert.ok(text.length > 'permissionpaymentguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionpaymentGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionpaymentGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
