'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./corswildcardguard.js');

const REASONS = ["CORSWILD_FLAG_OFF", "CORSWILD_REPORT_ONLY", "CORSWILD_MODE_INVALID", "CORSWILD_COUNT_OUT_OF_RANGE", "CORSWILD_ENDPOINT_INSECURE", "CORSWILD_ENDPOINT_TOO_LONG", "CORSWILD_NOTE_CONTROL", "CORSWILD_PATH_TRAVERSAL", "CORSWILD_ITEM_UNKNOWN", "CORSWILD_ITEM_DUPLICATE", "CORSWILD_ITEM_COUNT", "CORSWILD_BASELINE_EMPTY"];
const CLEAN = {
  "cors": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 1800,
    "endpoint": "https://cors.example.com/allow",
    "note": "cors-note",
    "storagePath": "policies/cors",
    "items": [
      "https://app.example.com"
    ],
    "baseline": [
      "cors"
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
  assert.strictEqual(typeof guard.evaluateCorswildcardGuard, 'function');
  assert.strictEqual(typeof guard.describeCorswildcardGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCorswildcardGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCorswildcardGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CORSWILD_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.enabled', false));
  assert.ok(hasKey(result, 'CORSWILD_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSWILD_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.reportOnly', true));
  assert.ok(hasKey(result, 'CORSWILD_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CORSWILD_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSWILD_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.lifetime', 599));
  assert.ok(hasKey(result, 'CORSWILD_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CORSWILD_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSWILD_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CORSWILD_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CORSWILD_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CORSWILD_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSWILD_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CORSWILD_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CORSWILD_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CORSWILD_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CORSWILD_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CORSWILD_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.baseline', []));
  assert.ok(hasKey(result, 'CORSWILD_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CORSWILD_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCorswildcardGuard(withValue('cors.enabled', false));
  const text = guard.describeCorswildcardGuard(result);
  assert.ok(text.includes('CORSWILD_FLAG_OFF'));
  assert.ok(text.length > 'corswildcardguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCorswildcardGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCorswildcardGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
