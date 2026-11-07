'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./redirectlimitguard.js');

const REASONS = ["REDLIM_FLAG_OFF", "REDLIM_REPORT_ONLY", "REDLIM_MODE_INVALID", "REDLIM_COUNT_OUT_OF_RANGE", "REDLIM_ENDPOINT_INSECURE", "REDLIM_ENDPOINT_TOO_LONG", "REDLIM_NOTE_CONTROL", "REDLIM_PATH_TRAVERSAL", "REDLIM_ITEM_UNKNOWN", "REDLIM_ITEM_DUPLICATE", "REDLIM_ITEM_COUNT", "REDLIM_BASELINE_EMPTY"];
const CLEAN = {
  "redirectLimit": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 5,
    "endpoint": "https://redirect.example.com/hop",
    "note": "redirect-note",
    "storagePath": "policies/redirect",
    "items": [
      "https"
    ],
    "baseline": [
      "redirect"
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
  assert.strictEqual(typeof guard.evaluateRedirectlimitGuard, 'function');
  assert.strictEqual(typeof guard.describeRedirectlimitGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateRedirectlimitGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateRedirectlimitGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule REDLIM_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.enabled', false));
  assert.ok(hasKey(result, 'REDLIM_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule REDLIM_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.reportOnly', true));
  assert.ok(hasKey(result, 'REDLIM_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.mode', "bogus-value"));
  assert.ok(hasKey(result, 'REDLIM_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule REDLIM_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.lifetime', 0));
  assert.ok(hasKey(result, 'REDLIM_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'REDLIM_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule REDLIM_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'REDLIM_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.note', "a\u0007b"));
  assert.ok(hasKey(result, 'REDLIM_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'REDLIM_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule REDLIM_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'REDLIM_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule REDLIM_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'REDLIM_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'REDLIM_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule REDLIM_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.baseline', []));
  assert.ok(hasKey(result, 'REDLIM_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'REDLIM_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateRedirectlimitGuard(withValue('redirectLimit.enabled', false));
  const text = guard.describeRedirectlimitGuard(result);
  assert.ok(text.includes('REDLIM_FLAG_OFF'));
  assert.ok(text.length > 'redirectlimitguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeRedirectlimitGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateRedirectlimitGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
