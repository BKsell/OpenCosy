'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./hstsmaxageguard.js');

const REASONS = ["HSTSAGE_FLAG_OFF", "HSTSAGE_REPORT_ONLY", "HSTSAGE_MODE_INVALID", "HSTSAGE_COUNT_OUT_OF_RANGE", "HSTSAGE_ENDPOINT_INSECURE", "HSTSAGE_ENDPOINT_TOO_LONG", "HSTSAGE_NOTE_CONTROL", "HSTSAGE_PATH_TRAVERSAL", "HSTSAGE_ITEM_UNKNOWN", "HSTSAGE_ITEM_DUPLICATE", "HSTSAGE_ITEM_COUNT", "HSTSAGE_BASELINE_EMPTY"];
const CLEAN = {
  "hsts": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 31536000,
    "endpoint": "https://hsts.example.com/apply",
    "note": "hsts-note",
    "storagePath": "policies/hsts",
    "items": [
      "includeSubDomains"
    ],
    "baseline": [
      "hsts"
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
  assert.strictEqual(typeof guard.evaluateHstsmaxageGuard, 'function');
  assert.strictEqual(typeof guard.describeHstsmaxageGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateHstsmaxageGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateHstsmaxageGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule HSTSAGE_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.enabled', false));
  assert.ok(hasKey(result, 'HSTSAGE_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSAGE_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.reportOnly', true));
  assert.ok(hasKey(result, 'HSTSAGE_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.mode', "bogus-value"));
  assert.ok(hasKey(result, 'HSTSAGE_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSAGE_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.lifetime', 31535999));
  assert.ok(hasKey(result, 'HSTSAGE_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'HSTSAGE_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSAGE_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'HSTSAGE_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.note', "a\u0007b"));
  assert.ok(hasKey(result, 'HSTSAGE_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'HSTSAGE_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSAGE_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'HSTSAGE_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSAGE_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'HSTSAGE_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'HSTSAGE_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSAGE_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.baseline', []));
  assert.ok(hasKey(result, 'HSTSAGE_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'HSTSAGE_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateHstsmaxageGuard(withValue('hsts.enabled', false));
  const text = guard.describeHstsmaxageGuard(result);
  assert.ok(text.includes('HSTSAGE_FLAG_OFF'));
  assert.ok(text.length > 'hstsmaxageguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeHstsmaxageGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateHstsmaxageGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
