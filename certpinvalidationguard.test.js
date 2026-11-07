'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./certpinvalidationguard.js');

const REASONS = ["CERTPIN_FLAG_OFF", "CERTPIN_REPORT_ONLY", "CERTPIN_MODE_INVALID", "CERTPIN_COUNT_OUT_OF_RANGE", "CERTPIN_ENDPOINT_INSECURE", "CERTPIN_ENDPOINT_TOO_LONG", "CERTPIN_NOTE_CONTROL", "CERTPIN_PATH_TRAVERSAL", "CERTPIN_ITEM_UNKNOWN", "CERTPIN_ITEM_DUPLICATE", "CERTPIN_ITEM_COUNT", "CERTPIN_BASELINE_EMPTY"];
const CLEAN = {
  "certPin": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 1200,
    "endpoint": "https://pin.example.com/cert",
    "note": "pin-note",
    "storagePath": "policies/pin",
    "items": [
      "sha256-pin-a"
    ],
    "baseline": [
      "pin"
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
  assert.strictEqual(typeof guard.evaluateCertpinvalidationGuard, 'function');
  assert.strictEqual(typeof guard.describeCertpinvalidationGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCertpinvalidationGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCertpinvalidationGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CERTPIN_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.enabled', false));
  assert.ok(hasKey(result, 'CERTPIN_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CERTPIN_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.reportOnly', true));
  assert.ok(hasKey(result, 'CERTPIN_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CERTPIN_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CERTPIN_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.lifetime', 299));
  assert.ok(hasKey(result, 'CERTPIN_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CERTPIN_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CERTPIN_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CERTPIN_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CERTPIN_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CERTPIN_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CERTPIN_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CERTPIN_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CERTPIN_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CERTPIN_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CERTPIN_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CERTPIN_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.baseline', []));
  assert.ok(hasKey(result, 'CERTPIN_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CERTPIN_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCertpinvalidationGuard(withValue('certPin.enabled', false));
  const text = guard.describeCertpinvalidationGuard(result);
  assert.ok(text.includes('CERTPIN_FLAG_OFF'));
  assert.ok(text.length > 'certpinvalidationguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCertpinvalidationGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCertpinvalidationGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
