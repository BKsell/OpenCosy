'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cookiessamesiteguard.js');

const REASONS = ["CKSS_FLAG_OFF", "CKSS_REPORT_ONLY", "CKSS_MODE_INVALID", "CKSS_COUNT_OUT_OF_RANGE", "CKSS_ENDPOINT_INSECURE", "CKSS_ENDPOINT_TOO_LONG", "CKSS_NOTE_CONTROL", "CKSS_PATH_TRAVERSAL", "CKSS_ITEM_UNKNOWN", "CKSS_ITEM_DUPLICATE", "CKSS_ITEM_COUNT", "CKSS_BASELINE_EMPTY"];
const CLEAN = {
  "cookieSameSite": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 3600,
    "endpoint": "https://samesite.example.com/set",
    "note": "samesite-note",
    "storagePath": "policies/samesite",
    "items": [
      "sid"
    ],
    "baseline": [
      "samesite"
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
  assert.strictEqual(typeof guard.evaluateCookiessamesiteGuard, 'function');
  assert.strictEqual(typeof guard.describeCookiessamesiteGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCookiessamesiteGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCookiessamesiteGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CKSS_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.enabled', false));
  assert.ok(hasKey(result, 'CKSS_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CKSS_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSS_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.reportOnly', true));
  assert.ok(hasKey(result, 'CKSS_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CKSS_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CKSS_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CKSS_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSS_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.lifetime', 899));
  assert.ok(hasKey(result, 'CKSS_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CKSS_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CKSS_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CKSS_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSS_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CKSS_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CKSS_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CKSS_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CKSS_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CKSS_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CKSS_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSS_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CKSS_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CKSS_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKSS_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CKSS_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CKSS_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CKSS_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CKSS_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKSS_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.baseline', []));
  assert.ok(hasKey(result, 'CKSS_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CKSS_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCookiessamesiteGuard(withValue('cookieSameSite.enabled', false));
  const text = guard.describeCookiessamesiteGuard(result);
  assert.ok(text.includes('CKSS_FLAG_OFF'));
  assert.ok(text.length > 'cookiessamesiteguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCookiessamesiteGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCookiessamesiteGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
