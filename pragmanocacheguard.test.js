'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./pragmanocacheguard.js');

const REASONS = ["PRAGMA_FLAG_OFF", "PRAGMA_REPORT_ONLY", "PRAGMA_MODE_INVALID", "PRAGMA_COUNT_OUT_OF_RANGE", "PRAGMA_ENDPOINT_INSECURE", "PRAGMA_ENDPOINT_TOO_LONG", "PRAGMA_NOTE_CONTROL", "PRAGMA_PATH_TRAVERSAL", "PRAGMA_ITEM_UNKNOWN", "PRAGMA_ITEM_DUPLICATE", "PRAGMA_ITEM_COUNT", "PRAGMA_BASELINE_EMPTY"];
const CLEAN = {
  "pragma": {
    "enabled": true,
    "reportOnly": false,
    "mode": "no-cache",
    "lifetime": 240,
    "endpoint": "https://pragma.example.com/legacy",
    "note": "pragma-note",
    "storagePath": "policies/pragma",
    "items": [
      "no-cache"
    ],
    "baseline": [
      "pragma"
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
  assert.strictEqual(typeof guard.evaluatePragmanocacheGuard, 'function');
  assert.strictEqual(typeof guard.describePragmanocacheGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePragmanocacheGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePragmanocacheGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PRAGMA_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.enabled', false));
  assert.ok(hasKey(result, 'PRAGMA_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PRAGMA_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.reportOnly', true));
  assert.ok(hasKey(result, 'PRAGMA_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PRAGMA_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PRAGMA_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.lifetime', 59));
  assert.ok(hasKey(result, 'PRAGMA_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PRAGMA_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PRAGMA_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PRAGMA_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PRAGMA_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PRAGMA_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PRAGMA_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PRAGMA_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PRAGMA_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PRAGMA_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.items', ["filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PRAGMA_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PRAGMA_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.baseline', []));
  assert.ok(hasKey(result, 'PRAGMA_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PRAGMA_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePragmanocacheGuard(withValue('pragma.enabled', false));
  const text = guard.describePragmanocacheGuard(result);
  assert.ok(text.includes('PRAGMA_FLAG_OFF'));
  assert.ok(text.length > 'pragmanocacheguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePragmanocacheGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePragmanocacheGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
