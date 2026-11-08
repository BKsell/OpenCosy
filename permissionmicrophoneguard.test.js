'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionmicrophoneguard.js');

const REASONS = ["PERMMIC_FLAG_OFF", "PERMMIC_REPORT_ONLY", "PERMMIC_MODE_INVALID", "PERMMIC_COUNT_OUT_OF_RANGE", "PERMMIC_ENDPOINT_INSECURE", "PERMMIC_ENDPOINT_TOO_LONG", "PERMMIC_NOTE_CONTROL", "PERMMIC_PATH_TRAVERSAL", "PERMMIC_ITEM_UNKNOWN", "PERMMIC_ITEM_DUPLICATE", "PERMMIC_ITEM_COUNT", "PERMMIC_BASELINE_EMPTY"];
const CLEAN = {
  "permMic": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 480,
    "endpoint": "https://mic.example.com/policy",
    "note": "mic-note",
    "storagePath": "policies/mic",
    "items": [
      "microphone=()"
    ],
    "baseline": [
      "mic"
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
  assert.strictEqual(typeof guard.evaluatePermissionmicrophoneGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionmicrophoneGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMMIC_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.enabled', false));
  assert.ok(hasKey(result, 'PERMMIC_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIC_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.reportOnly', true));
  assert.ok(hasKey(result, 'PERMMIC_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMMIC_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIC_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.lifetime', 119));
  assert.ok(hasKey(result, 'PERMMIC_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMMIC_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIC_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMMIC_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMMIC_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMMIC_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIC_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMMIC_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIC_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMMIC_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMMIC_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIC_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.baseline', []));
  assert.ok(hasKey(result, 'PERMMIC_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMMIC_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionmicrophoneGuard(withValue('permMic.enabled', false));
  const text = guard.describePermissionmicrophoneGuard(result);
  assert.ok(text.includes('PERMMIC_FLAG_OFF'));
  assert.ok(text.length > 'permissionmicrophoneguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionmicrophoneGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionmicrophoneGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
