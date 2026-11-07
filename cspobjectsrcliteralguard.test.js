'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspobjectsrcliteralguard.js');

const REASONS = ["CSPSOBJ_FLAG_OFF", "CSPSOBJ_REPORT_ONLY", "CSPSOBJ_MODE_INVALID", "CSPSOBJ_COUNT_OUT_OF_RANGE", "CSPSOBJ_ENDPOINT_INSECURE", "CSPSOBJ_ENDPOINT_TOO_LONG", "CSPSOBJ_NOTE_CONTROL", "CSPSOBJ_PATH_TRAVERSAL", "CSPSOBJ_ITEM_UNKNOWN", "CSPSOBJ_ITEM_DUPLICATE", "CSPSOBJ_ITEM_COUNT", "CSPSOBJ_BASELINE_EMPTY"];
const CLEAN = {
  "cspObject": {
    "enabled": true,
    "reportOnly": false,
    "mode": "none",
    "lifetime": 600,
    "endpoint": "https://media.example.com/object",
    "note": "object-lock",
    "storagePath": "policies/object",
    "items": [
      "none"
    ],
    "baseline": [
      "object"
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
  assert.strictEqual(typeof guard.evaluateCspobjectsrcliteralGuard, 'function');
  assert.strictEqual(typeof guard.describeCspobjectsrcliteralGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPSOBJ_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.enabled', false));
  assert.ok(hasKey(result, 'CSPSOBJ_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSOBJ_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.reportOnly', true));
  assert.ok(hasKey(result, 'CSPSOBJ_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPSOBJ_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSOBJ_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.lifetime', 59));
  assert.ok(hasKey(result, 'CSPSOBJ_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPSOBJ_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSOBJ_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPSOBJ_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPSOBJ_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPSOBJ_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSOBJ_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPSOBJ_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSOBJ_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPSOBJ_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPSOBJ_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSOBJ_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.baseline', []));
  assert.ok(hasKey(result, 'CSPSOBJ_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPSOBJ_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard(withValue('cspObject.enabled', false));
  const text = guard.describeCspobjectsrcliteralGuard(result);
  assert.ok(text.includes('CSPSOBJ_FLAG_OFF'));
  assert.ok(text.length > 'cspobjectsrcliteralguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspobjectsrcliteralGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspobjectsrcliteralGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
