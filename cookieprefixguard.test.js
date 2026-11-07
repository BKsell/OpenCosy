'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cookieprefixguard.js');

const REASONS = ["CKPFX_FLAG_OFF", "CKPFX_REPORT_ONLY", "CKPFX_MODE_INVALID", "CKPFX_COUNT_OUT_OF_RANGE", "CKPFX_ENDPOINT_INSECURE", "CKPFX_ENDPOINT_TOO_LONG", "CKPFX_NOTE_CONTROL", "CKPFX_PATH_TRAVERSAL", "CKPFX_ITEM_UNKNOWN", "CKPFX_ITEM_DUPLICATE", "CKPFX_ITEM_COUNT", "CKPFX_BASELINE_EMPTY"];
const CLEAN = {
  "cookiePrefix": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 3600,
    "endpoint": "https://prefix.example.com/set",
    "note": "prefix-note",
    "storagePath": "policies/prefix",
    "items": [
      "__Host-sid"
    ],
    "baseline": [
      "prefix"
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
  assert.strictEqual(typeof guard.evaluateCookieprefixGuard, 'function');
  assert.strictEqual(typeof guard.describeCookieprefixGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCookieprefixGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCookieprefixGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CKPFX_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.enabled', false));
  assert.ok(hasKey(result, 'CKPFX_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKPFX_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.reportOnly', true));
  assert.ok(hasKey(result, 'CKPFX_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CKPFX_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKPFX_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.lifetime', 899));
  assert.ok(hasKey(result, 'CKPFX_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CKPFX_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKPFX_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CKPFX_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CKPFX_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CKPFX_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKPFX_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CKPFX_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CKPFX_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CKPFX_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CKPFX_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CKPFX_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.baseline', []));
  assert.ok(hasKey(result, 'CKPFX_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CKPFX_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCookieprefixGuard(withValue('cookiePrefix.enabled', false));
  const text = guard.describeCookieprefixGuard(result);
  assert.ok(text.includes('CKPFX_FLAG_OFF'));
  assert.ok(text.length > 'cookieprefixguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCookieprefixGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCookieprefixGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
