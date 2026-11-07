'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./srirequireguard.js');

const REASONS = ["SRIREQ_FLAG_OFF", "SRIREQ_REPORT_ONLY", "SRIREQ_MODE_INVALID", "SRIREQ_COUNT_OUT_OF_RANGE", "SRIREQ_ENDPOINT_INSECURE", "SRIREQ_ENDPOINT_TOO_LONG", "SRIREQ_NOTE_CONTROL", "SRIREQ_PATH_TRAVERSAL", "SRIREQ_ITEM_UNKNOWN", "SRIREQ_ITEM_DUPLICATE", "SRIREQ_ITEM_COUNT", "SRIREQ_BASELINE_EMPTY"];
const CLEAN = {
  "sri": {
    "enabled": true,
    "reportOnly": false,
    "mode": "required",
    "lifetime": 1200,
    "endpoint": "https://sri.example.com/asset",
    "note": "sri-note",
    "storagePath": "policies/sri",
    "items": [
      "sha384-abc"
    ],
    "baseline": [
      "sri"
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
  assert.strictEqual(typeof guard.evaluateSrirequireGuard, 'function');
  assert.strictEqual(typeof guard.describeSrirequireGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateSrirequireGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateSrirequireGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule SRIREQ_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.enabled', false));
  assert.ok(hasKey(result, 'SRIREQ_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule SRIREQ_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.reportOnly', true));
  assert.ok(hasKey(result, 'SRIREQ_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.mode', "bogus-value"));
  assert.ok(hasKey(result, 'SRIREQ_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule SRIREQ_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.lifetime', 299));
  assert.ok(hasKey(result, 'SRIREQ_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'SRIREQ_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule SRIREQ_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'SRIREQ_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.note', "a\u0007b"));
  assert.ok(hasKey(result, 'SRIREQ_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'SRIREQ_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule SRIREQ_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'SRIREQ_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule SRIREQ_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'SRIREQ_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'SRIREQ_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule SRIREQ_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.baseline', []));
  assert.ok(hasKey(result, 'SRIREQ_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'SRIREQ_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateSrirequireGuard(withValue('sri.enabled', false));
  const text = guard.describeSrirequireGuard(result);
  assert.ok(text.includes('SRIREQ_FLAG_OFF'));
  assert.ok(text.length > 'srirequireguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeSrirequireGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateSrirequireGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
