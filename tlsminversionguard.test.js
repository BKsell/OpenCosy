'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./tlsminversionguard.js');

const REASONS = ["TLSMIN_FLAG_OFF", "TLSMIN_REPORT_ONLY", "TLSMIN_MODE_INVALID", "TLSMIN_COUNT_OUT_OF_RANGE", "TLSMIN_ENDPOINT_INSECURE", "TLSMIN_ENDPOINT_TOO_LONG", "TLSMIN_NOTE_CONTROL", "TLSMIN_PATH_TRAVERSAL", "TLSMIN_ITEM_UNKNOWN", "TLSMIN_ITEM_DUPLICATE", "TLSMIN_ITEM_COUNT", "TLSMIN_BASELINE_EMPTY"];
const CLEAN = {
  "tls": {
    "enabled": true,
    "reportOnly": false,
    "mode": "1.2",
    "lifetime": 1200,
    "endpoint": "https://tls.example.com/handshake",
    "note": "tls-note",
    "storagePath": "policies/tls",
    "items": [
      "TLS1.2"
    ],
    "baseline": [
      "tls"
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
  assert.strictEqual(typeof guard.evaluateTlsminversionGuard, 'function');
  assert.strictEqual(typeof guard.describeTlsminversionGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateTlsminversionGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateTlsminversionGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule TLSMIN_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.enabled', false));
  assert.ok(hasKey(result, 'TLSMIN_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule TLSMIN_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.reportOnly', true));
  assert.ok(hasKey(result, 'TLSMIN_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.mode', "bogus-value"));
  assert.ok(hasKey(result, 'TLSMIN_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule TLSMIN_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.lifetime', 299));
  assert.ok(hasKey(result, 'TLSMIN_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'TLSMIN_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule TLSMIN_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'TLSMIN_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.note', "a\u0007b"));
  assert.ok(hasKey(result, 'TLSMIN_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'TLSMIN_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule TLSMIN_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'TLSMIN_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule TLSMIN_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'TLSMIN_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'TLSMIN_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule TLSMIN_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.baseline', []));
  assert.ok(hasKey(result, 'TLSMIN_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'TLSMIN_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateTlsminversionGuard(withValue('tls.enabled', false));
  const text = guard.describeTlsminversionGuard(result);
  assert.ok(text.includes('TLSMIN_FLAG_OFF'));
  assert.ok(text.length > 'tlsminversionguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeTlsminversionGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateTlsminversionGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
