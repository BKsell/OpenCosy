'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionmidiguard.js');

const REASONS = ["PERMMIDI_FLAG_OFF", "PERMMIDI_REPORT_ONLY", "PERMMIDI_MODE_INVALID", "PERMMIDI_COUNT_OUT_OF_RANGE", "PERMMIDI_ENDPOINT_INSECURE", "PERMMIDI_ENDPOINT_TOO_LONG", "PERMMIDI_NOTE_CONTROL", "PERMMIDI_PATH_TRAVERSAL", "PERMMIDI_ITEM_UNKNOWN", "PERMMIDI_ITEM_DUPLICATE", "PERMMIDI_ITEM_COUNT", "PERMMIDI_BASELINE_EMPTY"];
const CLEAN = {
  "permMidi": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 300,
    "endpoint": "https://midi.example.com/policy",
    "note": "midi-note",
    "storagePath": "policies/midi",
    "items": [
      "midi=()"
    ],
    "baseline": [
      "midi"
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
  assert.strictEqual(typeof guard.evaluatePermissionmidiGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionmidiGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionmidiGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionmidiGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMMIDI_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.enabled', false));
  assert.ok(hasKey(result, 'PERMMIDI_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIDI_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.reportOnly', true));
  assert.ok(hasKey(result, 'PERMMIDI_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMMIDI_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIDI_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.lifetime', 59));
  assert.ok(hasKey(result, 'PERMMIDI_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMMIDI_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIDI_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMMIDI_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMMIDI_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMMIDI_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIDI_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMMIDI_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMMIDI_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMMIDI_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMMIDI_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMMIDI_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.baseline', []));
  assert.ok(hasKey(result, 'PERMMIDI_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMMIDI_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionmidiGuard(withValue('permMidi.enabled', false));
  const text = guard.describePermissionmidiGuard(result);
  assert.ok(text.includes('PERMMIDI_FLAG_OFF'));
  assert.ok(text.length > 'permissionmidiguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionmidiGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionmidiGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
