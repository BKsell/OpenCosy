'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cipherallowlistguard.js');

const REASONS = ["CIPHER_FLAG_OFF", "CIPHER_REPORT_ONLY", "CIPHER_MODE_INVALID", "CIPHER_COUNT_OUT_OF_RANGE", "CIPHER_ENDPOINT_INSECURE", "CIPHER_ENDPOINT_TOO_LONG", "CIPHER_NOTE_CONTROL", "CIPHER_PATH_TRAVERSAL", "CIPHER_ITEM_UNKNOWN", "CIPHER_ITEM_DUPLICATE", "CIPHER_ITEM_COUNT", "CIPHER_BASELINE_EMPTY"];
const CLEAN = {
  "cipher": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 1200,
    "endpoint": "https://cipher.example.com/suite",
    "note": "cipher-note",
    "storagePath": "policies/cipher",
    "items": [
      "TLS_AES_256_GCM_SHA384"
    ],
    "baseline": [
      "cipher"
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
  assert.strictEqual(typeof guard.evaluateCipherallowlistGuard, 'function');
  assert.strictEqual(typeof guard.describeCipherallowlistGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCipherallowlistGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCipherallowlistGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CIPHER_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.enabled', false));
  assert.ok(hasKey(result, 'CIPHER_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CIPHER_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.reportOnly', true));
  assert.ok(hasKey(result, 'CIPHER_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CIPHER_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CIPHER_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.lifetime', 299));
  assert.ok(hasKey(result, 'CIPHER_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CIPHER_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CIPHER_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CIPHER_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CIPHER_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CIPHER_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CIPHER_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CIPHER_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CIPHER_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CIPHER_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CIPHER_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CIPHER_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.baseline', []));
  assert.ok(hasKey(result, 'CIPHER_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CIPHER_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCipherallowlistGuard(withValue('cipher.enabled', false));
  const text = guard.describeCipherallowlistGuard(result);
  assert.ok(text.includes('CIPHER_FLAG_OFF'));
  assert.ok(text.length > 'cipherallowlistguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCipherallowlistGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCipherallowlistGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
