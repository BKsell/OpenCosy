'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./crossoriginisolatedguard.js');

const REASONS = ["COISO_FLAG_OFF", "COISO_REPORT_ONLY", "COISO_MODE_INVALID", "COISO_COUNT_OUT_OF_RANGE", "COISO_ENDPOINT_INSECURE", "COISO_ENDPOINT_TOO_LONG", "COISO_NOTE_CONTROL", "COISO_PATH_TRAVERSAL", "COISO_ITEM_UNKNOWN", "COISO_ITEM_DUPLICATE", "COISO_ITEM_COUNT", "COISO_BASELINE_EMPTY"];
const CLEAN = {
  "coiso": {
    "enabled": true,
    "reportOnly": false,
    "mode": "isolated",
    "lifetime": 600,
    "endpoint": "https://isolate.example.com/page",
    "note": "iso-note",
    "storagePath": "policies/iso",
    "items": [
      "same-origin"
    ],
    "baseline": [
      "iso"
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
  assert.strictEqual(typeof guard.evaluateCrossoriginisolatedGuard, 'function');
  assert.strictEqual(typeof guard.describeCrossoriginisolatedGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule COISO_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.enabled', false));
  assert.ok(hasKey(result, 'COISO_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'COISO_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule COISO_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.reportOnly', true));
  assert.ok(hasKey(result, 'COISO_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'COISO_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.mode', "bogus-value"));
  assert.ok(hasKey(result, 'COISO_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'COISO_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule COISO_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.lifetime', 179));
  assert.ok(hasKey(result, 'COISO_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'COISO_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'COISO_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'COISO_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule COISO_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'COISO_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'COISO_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.note', "a\u0007b"));
  assert.ok(hasKey(result, 'COISO_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'COISO_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'COISO_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'COISO_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule COISO_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'COISO_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'COISO_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule COISO_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'COISO_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'COISO_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'COISO_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'COISO_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule COISO_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.baseline', []));
  assert.ok(hasKey(result, 'COISO_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'COISO_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCrossoriginisolatedGuard(withValue('coiso.enabled', false));
  const text = guard.describeCrossoriginisolatedGuard(result);
  assert.ok(text.includes('COISO_FLAG_OFF'));
  assert.ok(text.length > 'crossoriginisolatedguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCrossoriginisolatedGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCrossoriginisolatedGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
