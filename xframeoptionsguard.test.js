'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./xframeoptionsguard.js');

const REASONS = ["XFRAME_FLAG_OFF", "XFRAME_REPORT_ONLY", "XFRAME_MODE_INVALID", "XFRAME_COUNT_OUT_OF_RANGE", "XFRAME_ENDPOINT_INSECURE", "XFRAME_ENDPOINT_TOO_LONG", "XFRAME_NOTE_CONTROL", "XFRAME_PATH_TRAVERSAL", "XFRAME_ITEM_UNKNOWN", "XFRAME_ITEM_DUPLICATE", "XFRAME_ITEM_COUNT", "XFRAME_BASELINE_EMPTY"];
const CLEAN = {
  "xframe": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 300,
    "endpoint": "https://clickjack.example.com/guard",
    "note": "frame-note",
    "storagePath": "policies/xframe",
    "items": [
      "deny"
    ],
    "baseline": [
      "clickjack"
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
  assert.strictEqual(typeof guard.evaluateXframeoptionsGuard, 'function');
  assert.strictEqual(typeof guard.describeXframeoptionsGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateXframeoptionsGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateXframeoptionsGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule XFRAME_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.enabled', false));
  assert.ok(hasKey(result, 'XFRAME_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule XFRAME_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.reportOnly', true));
  assert.ok(hasKey(result, 'XFRAME_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.mode', "bogus-value"));
  assert.ok(hasKey(result, 'XFRAME_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule XFRAME_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.lifetime', 59));
  assert.ok(hasKey(result, 'XFRAME_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'XFRAME_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule XFRAME_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'XFRAME_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.note', "a\u0007b"));
  assert.ok(hasKey(result, 'XFRAME_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'XFRAME_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule XFRAME_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'XFRAME_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule XFRAME_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'XFRAME_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.items', ["filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'XFRAME_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule XFRAME_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.baseline', []));
  assert.ok(hasKey(result, 'XFRAME_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'XFRAME_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateXframeoptionsGuard(withValue('xframe.enabled', false));
  const text = guard.describeXframeoptionsGuard(result);
  assert.ok(text.includes('XFRAME_FLAG_OFF'));
  assert.ok(text.length > 'xframeoptionsguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeXframeoptionsGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateXframeoptionsGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
