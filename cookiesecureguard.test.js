'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cookiesecureguard.js');

const REASONS = ["CKSEC_FLAG_OFF", "CKSEC_REPORT_ONLY", "CKSEC_MODE_INVALID", "CKSEC_COUNT_OUT_OF_RANGE", "CKSEC_ENDPOINT_INSECURE", "CKSEC_ENDPOINT_TOO_LONG", "CKSEC_NOTE_CONTROL", "CKSEC_PATH_TRAVERSAL", "CKSEC_ITEM_UNKNOWN", "CKSEC_ITEM_DUPLICATE", "CKSEC_ITEM_COUNT", "CKSEC_BASELINE_EMPTY"];
const CLEAN = {
  "cookieSecure": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 3600,
    "endpoint": "https://securecookie.example.com/set",
    "note": "secure-note",
    "storagePath": "policies/secure",
    "items": [
      "sid"
    ],
    "baseline": [
      "secure"
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
  assert.strictEqual(typeof guard.evaluateCookiesecureGuard, 'function');
  assert.strictEqual(typeof guard.describeCookiesecureGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCookiesecureGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCookiesecureGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CKSEC_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.enabled', false));
  assert.ok(hasKey(result, 'CKSEC_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSEC_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.reportOnly', true));
  assert.ok(hasKey(result, 'CKSEC_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CKSEC_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSEC_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.lifetime', 899));
  assert.ok(hasKey(result, 'CKSEC_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CKSEC_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSEC_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CKSEC_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CKSEC_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CKSEC_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSEC_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CKSEC_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSEC_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CKSEC_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CKSEC_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSEC_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.baseline', []));
  assert.ok(hasKey(result, 'CKSEC_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CKSEC_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCookiesecureGuard(withValue('cookieSecure.enabled', false));
  const text = guard.describeCookiesecureGuard(result);
  assert.ok(text.includes('CKSEC_FLAG_OFF'));
  assert.ok(text.length > 'cookiesecureguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCookiesecureGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCookiesecureGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
