'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspframeguard.js');

const REASONS = ["CSPFRM_FLAG_OFF", "CSPFRM_REPORT_ONLY", "CSPFRM_MODE_INVALID", "CSPFRM_COUNT_OUT_OF_RANGE", "CSPFRM_ENDPOINT_INSECURE", "CSPFRM_ENDPOINT_TOO_LONG", "CSPFRM_NOTE_CONTROL", "CSPFRM_PATH_TRAVERSAL", "CSPFRM_ITEM_UNKNOWN", "CSPFRM_ITEM_DUPLICATE", "CSPFRM_ITEM_COUNT", "CSPFRM_BASELINE_EMPTY"];
const CLEAN = {
  "cspFrame": {
    "enabled": true,
    "reportOnly": false,
    "mode": "self",
    "lifetime": 1200,
    "endpoint": "https://frame.example.com/embed",
    "note": "frame-lock",
    "storagePath": "policies/frame",
    "items": [
      "self"
    ],
    "baseline": [
      "frame"
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
  assert.strictEqual(typeof guard.evaluateCspframeGuard, 'function');
  assert.strictEqual(typeof guard.describeCspframeGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspframeGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspframeGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPFRM_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.enabled', false));
  assert.ok(hasKey(result, 'CSPFRM_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPFRM_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.reportOnly', true));
  assert.ok(hasKey(result, 'CSPFRM_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPFRM_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPFRM_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.lifetime', 299));
  assert.ok(hasKey(result, 'CSPFRM_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPFRM_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPFRM_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPFRM_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPFRM_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPFRM_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPFRM_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPFRM_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPFRM_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPFRM_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPFRM_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPFRM_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.baseline', []));
  assert.ok(hasKey(result, 'CSPFRM_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPFRM_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspframeGuard(withValue('cspFrame.enabled', false));
  const text = guard.describeCspframeGuard(result);
  assert.ok(text.includes('CSPFRM_FLAG_OFF'));
  assert.ok(text.length > 'cspframeguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspframeGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspframeGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
