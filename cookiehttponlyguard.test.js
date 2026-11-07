'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cookiehttponlyguard.js');

const REASONS = ["CKHTTP_FLAG_OFF", "CKHTTP_REPORT_ONLY", "CKHTTP_MODE_INVALID", "CKHTTP_COUNT_OUT_OF_RANGE", "CKHTTP_ENDPOINT_INSECURE", "CKHTTP_ENDPOINT_TOO_LONG", "CKHTTP_NOTE_CONTROL", "CKHTTP_PATH_TRAVERSAL", "CKHTTP_ITEM_UNKNOWN", "CKHTTP_ITEM_DUPLICATE", "CKHTTP_ITEM_COUNT", "CKHTTP_BASELINE_EMPTY"];
const CLEAN = {
  "cookieHttp": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 3600,
    "endpoint": "https://cookie.example.com/set",
    "note": "cookie-note",
    "storagePath": "policies/cookie",
    "items": [
      "sid"
    ],
    "baseline": [
      "cookie"
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
  assert.strictEqual(typeof guard.evaluateCookiehttponlyGuard, 'function');
  assert.strictEqual(typeof guard.describeCookiehttponlyGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCookiehttponlyGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCookiehttponlyGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CKHTTP_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.enabled', false));
  assert.ok(hasKey(result, 'CKHTTP_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKHTTP_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.reportOnly', true));
  assert.ok(hasKey(result, 'CKHTTP_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CKHTTP_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKHTTP_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.lifetime', 899));
  assert.ok(hasKey(result, 'CKHTTP_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CKHTTP_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKHTTP_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CKHTTP_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CKHTTP_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CKHTTP_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKHTTP_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CKHTTP_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKHTTP_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CKHTTP_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CKHTTP_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKHTTP_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.baseline', []));
  assert.ok(hasKey(result, 'CKHTTP_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CKHTTP_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCookiehttponlyGuard(withValue('cookieHttp.enabled', false));
  const text = guard.describeCookiehttponlyGuard(result);
  assert.ok(text.includes('CKHTTP_FLAG_OFF'));
  assert.ok(text.length > 'cookiehttponlyguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCookiehttponlyGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCookiehttponlyGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
