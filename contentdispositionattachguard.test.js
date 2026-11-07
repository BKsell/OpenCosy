'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./contentdispositionattachguard.js');

const REASONS = ["CDATT_FLAG_OFF", "CDATT_REPORT_ONLY", "CDATT_MODE_INVALID", "CDATT_COUNT_OUT_OF_RANGE", "CDATT_ENDPOINT_INSECURE", "CDATT_ENDPOINT_TOO_LONG", "CDATT_NOTE_CONTROL", "CDATT_PATH_TRAVERSAL", "CDATT_ITEM_UNKNOWN", "CDATT_ITEM_DUPLICATE", "CDATT_ITEM_COUNT", "CDATT_BASELINE_EMPTY"];
const CLEAN = {
  "disposition": {
    "enabled": true,
    "reportOnly": false,
    "mode": "attachment",
    "lifetime": 300,
    "endpoint": "https://download.example.com/file",
    "note": "download-note",
    "storagePath": "policies/download",
    "items": [
      "attachment"
    ],
    "baseline": [
      "download"
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
  assert.strictEqual(typeof guard.evaluateContentdispositionattachGuard, 'function');
  assert.strictEqual(typeof guard.describeContentdispositionattachGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateContentdispositionattachGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateContentdispositionattachGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CDATT_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.enabled', false));
  assert.ok(hasKey(result, 'CDATT_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CDATT_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CDATT_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.reportOnly', true));
  assert.ok(hasKey(result, 'CDATT_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CDATT_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CDATT_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CDATT_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CDATT_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.lifetime', 59));
  assert.ok(hasKey(result, 'CDATT_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CDATT_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CDATT_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CDATT_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CDATT_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CDATT_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CDATT_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CDATT_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CDATT_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CDATT_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CDATT_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CDATT_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CDATT_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CDATT_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CDATT_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CDATT_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CDATT_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CDATT_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CDATT_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CDATT_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.baseline', []));
  assert.ok(hasKey(result, 'CDATT_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CDATT_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateContentdispositionattachGuard(withValue('disposition.enabled', false));
  const text = guard.describeContentdispositionattachGuard(result);
  assert.ok(text.includes('CDATT_FLAG_OFF'));
  assert.ok(text.length > 'contentdispositionattachguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeContentdispositionattachGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateContentdispositionattachGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
