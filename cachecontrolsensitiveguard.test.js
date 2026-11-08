'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cachecontrolsensitiveguard.js');

const REASONS = ["CCSENS_FLAG_OFF", "CCSENS_REPORT_ONLY", "CCSENS_MODE_INVALID", "CCSENS_COUNT_OUT_OF_RANGE", "CCSENS_ENDPOINT_INSECURE", "CCSENS_ENDPOINT_TOO_LONG", "CCSENS_NOTE_CONTROL", "CCSENS_PATH_TRAVERSAL", "CCSENS_ITEM_UNKNOWN", "CCSENS_ITEM_DUPLICATE", "CCSENS_ITEM_COUNT", "CCSENS_BASELINE_EMPTY"];
const CLEAN = {
  "cacheSensitive": {
    "enabled": true,
    "reportOnly": false,
    "mode": "no-store",
    "lifetime": 240,
    "endpoint": "https://cache.example.com/sensitive",
    "note": "cache-note",
    "storagePath": "policies/cache",
    "items": [
      "no-store"
    ],
    "baseline": [
      "cache"
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
  assert.strictEqual(typeof guard.evaluateCachecontrolsensitiveGuard, 'function');
  assert.strictEqual(typeof guard.describeCachecontrolsensitiveGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CCSENS_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.enabled', false));
  assert.ok(hasKey(result, 'CCSENS_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CCSENS_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.reportOnly', true));
  assert.ok(hasKey(result, 'CCSENS_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CCSENS_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CCSENS_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.lifetime', 59));
  assert.ok(hasKey(result, 'CCSENS_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CCSENS_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CCSENS_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CCSENS_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CCSENS_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CCSENS_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CCSENS_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CCSENS_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CCSENS_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CCSENS_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CCSENS_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CCSENS_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.baseline', []));
  assert.ok(hasKey(result, 'CCSENS_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CCSENS_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard(withValue('cacheSensitive.enabled', false));
  const text = guard.describeCachecontrolsensitiveGuard(result);
  assert.ok(text.includes('CCSENS_FLAG_OFF'));
  assert.ok(text.length > 'cachecontrolsensitiveguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCachecontrolsensitiveGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCachecontrolsensitiveGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
