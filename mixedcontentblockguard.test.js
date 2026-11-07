'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./mixedcontentblockguard.js');

const REASONS = ["MIXBLK_FLAG_OFF", "MIXBLK_REPORT_ONLY", "MIXBLK_MODE_INVALID", "MIXBLK_COUNT_OUT_OF_RANGE", "MIXBLK_ENDPOINT_INSECURE", "MIXBLK_ENDPOINT_TOO_LONG", "MIXBLK_NOTE_CONTROL", "MIXBLK_PATH_TRAVERSAL", "MIXBLK_ITEM_UNKNOWN", "MIXBLK_ITEM_DUPLICATE", "MIXBLK_ITEM_COUNT", "MIXBLK_BASELINE_EMPTY"];
const CLEAN = {
  "mixed": {
    "enabled": true,
    "reportOnly": false,
    "mode": "block",
    "lifetime": 900,
    "endpoint": "https://mixed.example.com/block",
    "note": "mixed-note",
    "storagePath": "policies/mixed",
    "items": [
      "blockable"
    ],
    "baseline": [
      "mixed"
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
  assert.strictEqual(typeof guard.evaluateMixedcontentblockGuard, 'function');
  assert.strictEqual(typeof guard.describeMixedcontentblockGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateMixedcontentblockGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateMixedcontentblockGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule MIXBLK_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.enabled', false));
  assert.ok(hasKey(result, 'MIXBLK_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule MIXBLK_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.reportOnly', true));
  assert.ok(hasKey(result, 'MIXBLK_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.mode', "bogus-value"));
  assert.ok(hasKey(result, 'MIXBLK_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule MIXBLK_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.lifetime', 299));
  assert.ok(hasKey(result, 'MIXBLK_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'MIXBLK_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule MIXBLK_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'MIXBLK_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.note', "a\u0007b"));
  assert.ok(hasKey(result, 'MIXBLK_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'MIXBLK_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule MIXBLK_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'MIXBLK_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule MIXBLK_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'MIXBLK_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'MIXBLK_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule MIXBLK_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.baseline', []));
  assert.ok(hasKey(result, 'MIXBLK_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'MIXBLK_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateMixedcontentblockGuard(withValue('mixed.enabled', false));
  const text = guard.describeMixedcontentblockGuard(result);
  assert.ok(text.includes('MIXBLK_FLAG_OFF'));
  assert.ok(text.length > 'mixedcontentblockguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeMixedcontentblockGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateMixedcontentblockGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
