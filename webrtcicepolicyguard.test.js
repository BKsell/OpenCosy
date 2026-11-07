'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./webrtcicepolicyguard.js');

const REASONS = ["WEBRTC_FLAG_OFF", "WEBRTC_REPORT_ONLY", "WEBRTC_MODE_INVALID", "WEBRTC_COUNT_OUT_OF_RANGE", "WEBRTC_ENDPOINT_INSECURE", "WEBRTC_ENDPOINT_TOO_LONG", "WEBRTC_NOTE_CONTROL", "WEBRTC_PATH_TRAVERSAL", "WEBRTC_ITEM_UNKNOWN", "WEBRTC_ITEM_DUPLICATE", "WEBRTC_ITEM_COUNT", "WEBRTC_BASELINE_EMPTY"];
const CLEAN = {
  "webrtc": {
    "enabled": true,
    "reportOnly": false,
    "mode": "relay",
    "lifetime": 600,
    "endpoint": "https://ice.example.com/policy",
    "note": "ice-note",
    "storagePath": "policies/ice",
    "items": [
      "relay"
    ],
    "baseline": [
      "ice"
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
  assert.strictEqual(typeof guard.evaluateWebrtcicepolicyGuard, 'function');
  assert.strictEqual(typeof guard.describeWebrtcicepolicyGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule WEBRTC_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.enabled', false));
  assert.ok(hasKey(result, 'WEBRTC_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule WEBRTC_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.reportOnly', true));
  assert.ok(hasKey(result, 'WEBRTC_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.mode', "bogus-value"));
  assert.ok(hasKey(result, 'WEBRTC_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule WEBRTC_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.lifetime', 179));
  assert.ok(hasKey(result, 'WEBRTC_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'WEBRTC_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule WEBRTC_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'WEBRTC_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.note', "a\u0007b"));
  assert.ok(hasKey(result, 'WEBRTC_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'WEBRTC_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule WEBRTC_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'WEBRTC_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule WEBRTC_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'WEBRTC_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'WEBRTC_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule WEBRTC_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.baseline', []));
  assert.ok(hasKey(result, 'WEBRTC_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'WEBRTC_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateWebrtcicepolicyGuard(withValue('webrtc.enabled', false));
  const text = guard.describeWebrtcicepolicyGuard(result);
  assert.ok(text.includes('WEBRTC_FLAG_OFF'));
  assert.ok(text.length > 'webrtcicepolicyguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeWebrtcicepolicyGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateWebrtcicepolicyGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
