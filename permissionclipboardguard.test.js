'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissionclipboardguard.js');

const REASONS = ["PERMCLP_FLAG_OFF", "PERMCLP_REPORT_ONLY", "PERMCLP_MODE_INVALID", "PERMCLP_COUNT_OUT_OF_RANGE", "PERMCLP_ENDPOINT_INSECURE", "PERMCLP_ENDPOINT_TOO_LONG", "PERMCLP_NOTE_CONTROL", "PERMCLP_PATH_TRAVERSAL", "PERMCLP_ITEM_UNKNOWN", "PERMCLP_ITEM_DUPLICATE", "PERMCLP_ITEM_COUNT", "PERMCLP_BASELINE_EMPTY"];
const CLEAN = {
  "permClip": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 360,
    "endpoint": "https://clip.example.com/policy",
    "note": "clip-note",
    "storagePath": "policies/clip",
    "items": [
      "clipboard-read=()"
    ],
    "baseline": [
      "clip"
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
  assert.strictEqual(typeof guard.evaluatePermissionclipboardGuard, 'function');
  assert.strictEqual(typeof guard.describePermissionclipboardGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissionclipboardGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissionclipboardGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMCLP_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.enabled', false));
  assert.ok(hasKey(result, 'PERMCLP_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCLP_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.reportOnly', true));
  assert.ok(hasKey(result, 'PERMCLP_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMCLP_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCLP_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.lifetime', 89));
  assert.ok(hasKey(result, 'PERMCLP_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMCLP_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCLP_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMCLP_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMCLP_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMCLP_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCLP_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMCLP_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMCLP_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMCLP_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMCLP_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMCLP_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.baseline', []));
  assert.ok(hasKey(result, 'PERMCLP_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMCLP_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissionclipboardGuard(withValue('permClip.enabled', false));
  const text = guard.describePermissionclipboardGuard(result);
  assert.ok(text.includes('PERMCLP_FLAG_OFF'));
  assert.ok(text.length > 'permissionclipboardguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissionclipboardGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissionclipboardGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
