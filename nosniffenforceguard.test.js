'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./nosniffenforceguard.js');

const REASONS = ["NOSNIFF_FLAG_OFF", "NOSNIFF_REPORT_ONLY", "NOSNIFF_MODE_INVALID", "NOSNIFF_COUNT_OUT_OF_RANGE", "NOSNIFF_ENDPOINT_INSECURE", "NOSNIFF_ENDPOINT_TOO_LONG", "NOSNIFF_NOTE_CONTROL", "NOSNIFF_PATH_TRAVERSAL", "NOSNIFF_ITEM_UNKNOWN", "NOSNIFF_ITEM_DUPLICATE", "NOSNIFF_ITEM_COUNT", "NOSNIFF_BASELINE_EMPTY"];
const CLEAN = {
  "nosniff": {
    "enabled": true,
    "reportOnly": false,
    "mode": "nosniff",
    "lifetime": 300,
    "endpoint": "https://mime.example.com/guard",
    "note": "mime-note",
    "storagePath": "policies/mime",
    "items": [
      "nosniff"
    ],
    "baseline": [
      "mime"
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
  assert.strictEqual(typeof guard.evaluateNosniffenforceGuard, 'function');
  assert.strictEqual(typeof guard.describeNosniffenforceGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateNosniffenforceGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateNosniffenforceGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule NOSNIFF_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.enabled', false));
  assert.ok(hasKey(result, 'NOSNIFF_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule NOSNIFF_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.reportOnly', true));
  assert.ok(hasKey(result, 'NOSNIFF_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.mode', "bogus-value"));
  assert.ok(hasKey(result, 'NOSNIFF_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule NOSNIFF_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.lifetime', 59));
  assert.ok(hasKey(result, 'NOSNIFF_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'NOSNIFF_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule NOSNIFF_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'NOSNIFF_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.note', "a\u0007b"));
  assert.ok(hasKey(result, 'NOSNIFF_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'NOSNIFF_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule NOSNIFF_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'NOSNIFF_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule NOSNIFF_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'NOSNIFF_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.items', ["filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'NOSNIFF_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule NOSNIFF_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.baseline', []));
  assert.ok(hasKey(result, 'NOSNIFF_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'NOSNIFF_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateNosniffenforceGuard(withValue('nosniff.enabled', false));
  const text = guard.describeNosniffenforceGuard(result);
  assert.ok(text.includes('NOSNIFF_FLAG_OFF'));
  assert.ok(text.length > 'nosniffenforceguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeNosniffenforceGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateNosniffenforceGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
