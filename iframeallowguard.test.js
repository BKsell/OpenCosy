'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./iframeallowguard.js');

const REASONS = ["IFRALW_FLAG_OFF", "IFRALW_REPORT_ONLY", "IFRALW_MODE_INVALID", "IFRALW_COUNT_OUT_OF_RANGE", "IFRALW_ENDPOINT_INSECURE", "IFRALW_ENDPOINT_TOO_LONG", "IFRALW_NOTE_CONTROL", "IFRALW_PATH_TRAVERSAL", "IFRALW_ITEM_UNKNOWN", "IFRALW_ITEM_DUPLICATE", "IFRALW_ITEM_COUNT", "IFRALW_BASELINE_EMPTY"];
const CLEAN = {
  "iframeAllow": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 600,
    "endpoint": "https://iframe.example.com/embed",
    "note": "iframe-note",
    "storagePath": "policies/iframe",
    "items": [
      "camera=none"
    ],
    "baseline": [
      "iframe"
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
  assert.strictEqual(typeof guard.evaluateIframeallowGuard, 'function');
  assert.strictEqual(typeof guard.describeIframeallowGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateIframeallowGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateIframeallowGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule IFRALW_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.enabled', false));
  assert.ok(hasKey(result, 'IFRALW_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule IFRALW_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.reportOnly', true));
  assert.ok(hasKey(result, 'IFRALW_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.mode', "bogus-value"));
  assert.ok(hasKey(result, 'IFRALW_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule IFRALW_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.lifetime', 179));
  assert.ok(hasKey(result, 'IFRALW_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'IFRALW_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule IFRALW_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'IFRALW_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.note', "a\u0007b"));
  assert.ok(hasKey(result, 'IFRALW_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'IFRALW_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule IFRALW_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'IFRALW_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule IFRALW_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'IFRALW_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'IFRALW_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule IFRALW_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.baseline', []));
  assert.ok(hasKey(result, 'IFRALW_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'IFRALW_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateIframeallowGuard(withValue('iframeAllow.enabled', false));
  const text = guard.describeIframeallowGuard(result);
  assert.ok(text.includes('IFRALW_FLAG_OFF'));
  assert.ok(text.length > 'iframeallowguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeIframeallowGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateIframeallowGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
