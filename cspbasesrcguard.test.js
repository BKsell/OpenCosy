'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspbasesrcguard.js');

const REASONS = ["CSPBASE_FLAG_OFF", "CSPBASE_REPORT_ONLY", "CSPBASE_MODE_INVALID", "CSPBASE_COUNT_OUT_OF_RANGE", "CSPBASE_ENDPOINT_INSECURE", "CSPBASE_ENDPOINT_TOO_LONG", "CSPBASE_NOTE_CONTROL", "CSPBASE_PATH_TRAVERSAL", "CSPBASE_ITEM_UNKNOWN", "CSPBASE_ITEM_DUPLICATE", "CSPBASE_ITEM_COUNT", "CSPBASE_BASELINE_EMPTY"];
const CLEAN = {
  "cspBase": {
    "enabled": true,
    "reportOnly": false,
    "mode": "none",
    "lifetime": 900,
    "endpoint": "https://base.example.com/root",
    "note": "base-lock",
    "storagePath": "policies/base",
    "items": [
      "none"
    ],
    "baseline": [
      "base"
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
  assert.strictEqual(typeof guard.evaluateCspbasesrcGuard, 'function');
  assert.strictEqual(typeof guard.describeCspbasesrcGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspbasesrcGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspbasesrcGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPBASE_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.enabled', false));
  assert.ok(hasKey(result, 'CSPBASE_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPBASE_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.reportOnly', true));
  assert.ok(hasKey(result, 'CSPBASE_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPBASE_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPBASE_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.lifetime', 119));
  assert.ok(hasKey(result, 'CSPBASE_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPBASE_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPBASE_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPBASE_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPBASE_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPBASE_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPBASE_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPBASE_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPBASE_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPBASE_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPBASE_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPBASE_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.baseline', []));
  assert.ok(hasKey(result, 'CSPBASE_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPBASE_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspbasesrcGuard(withValue('cspBase.enabled', false));
  const text = guard.describeCspbasesrcGuard(result);
  assert.ok(text.includes('CSPBASE_FLAG_OFF'));
  assert.ok(text.length > 'cspbasesrcguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspbasesrcGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspbasesrcGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
