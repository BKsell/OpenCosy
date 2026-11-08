'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./hstspreloadlistguard.js');

const REASONS = ["HSTSPRE_FLAG_OFF", "HSTSPRE_REPORT_ONLY", "HSTSPRE_MODE_INVALID", "HSTSPRE_COUNT_OUT_OF_RANGE", "HSTSPRE_ENDPOINT_INSECURE", "HSTSPRE_ENDPOINT_TOO_LONG", "HSTSPRE_NOTE_CONTROL", "HSTSPRE_PATH_TRAVERSAL", "HSTSPRE_ITEM_UNKNOWN", "HSTSPRE_ITEM_DUPLICATE", "HSTSPRE_ITEM_COUNT", "HSTSPRE_BASELINE_EMPTY"];
const CLEAN = {
  "hstsPreload": {
    "enabled": true,
    "reportOnly": false,
    "mode": "full",
    "lifetime": 63072000,
    "endpoint": "https://preload.example.com/list",
    "note": "preload-note",
    "storagePath": "policies/preload",
    "items": [
      "domain-a"
    ],
    "baseline": [
      "preload"
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
  assert.strictEqual(typeof guard.evaluateHstspreloadlistGuard, 'function');
  assert.strictEqual(typeof guard.describeHstspreloadlistGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateHstspreloadlistGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateHstspreloadlistGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule HSTSPRE_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.enabled', false));
  assert.ok(hasKey(result, 'HSTSPRE_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSPRE_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.reportOnly', true));
  assert.ok(hasKey(result, 'HSTSPRE_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.mode', "bogus-value"));
  assert.ok(hasKey(result, 'HSTSPRE_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSPRE_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.lifetime', 31535999));
  assert.ok(hasKey(result, 'HSTSPRE_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'HSTSPRE_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSPRE_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'HSTSPRE_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.note', "a\u0007b"));
  assert.ok(hasKey(result, 'HSTSPRE_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'HSTSPRE_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSPRE_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'HSTSPRE_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule HSTSPRE_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'HSTSPRE_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'HSTSPRE_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule HSTSPRE_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.baseline', []));
  assert.ok(hasKey(result, 'HSTSPRE_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'HSTSPRE_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateHstspreloadlistGuard(withValue('hstsPreload.enabled', false));
  const text = guard.describeHstspreloadlistGuard(result);
  assert.ok(text.includes('HSTSPRE_FLAG_OFF'));
  assert.ok(text.length > 'hstspreloadlistguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeHstspreloadlistGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateHstspreloadlistGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
