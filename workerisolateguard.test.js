'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./workerisolateguard.js');

const REASONS = ["WKRISO_FLAG_OFF", "WKRISO_REPORT_ONLY", "WKRISO_MODE_INVALID", "WKRISO_COUNT_OUT_OF_RANGE", "WKRISO_ENDPOINT_INSECURE", "WKRISO_ENDPOINT_TOO_LONG", "WKRISO_NOTE_CONTROL", "WKRISO_PATH_TRAVERSAL", "WKRISO_ITEM_UNKNOWN", "WKRISO_ITEM_DUPLICATE", "WKRISO_ITEM_COUNT", "WKRISO_BASELINE_EMPTY"];
const CLEAN = {
  "worker": {
    "enabled": true,
    "reportOnly": false,
    "mode": "isolated",
    "lifetime": 600,
    "endpoint": "https://worker.example.com/scope",
    "note": "worker-note",
    "storagePath": "policies/worker",
    "items": [
      "dedicated"
    ],
    "baseline": [
      "worker"
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
  assert.strictEqual(typeof guard.evaluateWorkerisolateGuard, 'function');
  assert.strictEqual(typeof guard.describeWorkerisolateGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateWorkerisolateGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateWorkerisolateGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule WKRISO_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.enabled', false));
  assert.ok(hasKey(result, 'WKRISO_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule WKRISO_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.reportOnly', true));
  assert.ok(hasKey(result, 'WKRISO_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.mode', "bogus-value"));
  assert.ok(hasKey(result, 'WKRISO_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule WKRISO_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.lifetime', 179));
  assert.ok(hasKey(result, 'WKRISO_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'WKRISO_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule WKRISO_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'WKRISO_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.note', "a\u0007b"));
  assert.ok(hasKey(result, 'WKRISO_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'WKRISO_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule WKRISO_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'WKRISO_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule WKRISO_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'WKRISO_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'WKRISO_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule WKRISO_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.baseline', []));
  assert.ok(hasKey(result, 'WKRISO_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'WKRISO_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateWorkerisolateGuard(withValue('worker.enabled', false));
  const text = guard.describeWorkerisolateGuard(result);
  assert.ok(text.includes('WKRISO_FLAG_OFF'));
  assert.ok(text.length > 'workerisolateguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeWorkerisolateGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateWorkerisolateGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
