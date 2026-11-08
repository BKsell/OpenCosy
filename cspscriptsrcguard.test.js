'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspscriptsrcguard.js');

const REASONS = ["CSPSRC_FLAG_OFF", "CSPSRC_REPORT_ONLY", "CSPSRC_MODE_INVALID", "CSPSRC_COUNT_OUT_OF_RANGE", "CSPSRC_ENDPOINT_INSECURE", "CSPSRC_ENDPOINT_TOO_LONG", "CSPSRC_NOTE_CONTROL", "CSPSRC_PATH_TRAVERSAL", "CSPSRC_ITEM_UNKNOWN", "CSPSRC_ITEM_DUPLICATE", "CSPSRC_ITEM_COUNT", "CSPSRC_BASELINE_EMPTY"];
const CLEAN = {
  "cspScript": {
    "enabled": true,
    "reportOnly": false,
    "mode": "nonce",
    "lifetime": 2400,
    "endpoint": "https://scripts.example.com/main.js",
    "note": "script-note",
    "storagePath": "policies/script",
    "items": [
      "nonce-abc"
    ],
    "baseline": [
      "script"
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
  assert.strictEqual(typeof guard.evaluateCspscriptsrcGuard, 'function');
  assert.strictEqual(typeof guard.describeCspscriptsrcGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspscriptsrcGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspscriptsrcGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPSRC_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.enabled', false));
  assert.ok(hasKey(result, 'CSPSRC_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSRC_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.reportOnly', true));
  assert.ok(hasKey(result, 'CSPSRC_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPSRC_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSRC_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.lifetime', 899));
  assert.ok(hasKey(result, 'CSPSRC_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPSRC_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSRC_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPSRC_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPSRC_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPSRC_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSRC_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPSRC_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPSRC_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPSRC_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPSRC_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPSRC_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.baseline', []));
  assert.ok(hasKey(result, 'CSPSRC_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPSRC_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspscriptsrcGuard(withValue('cspScript.enabled', false));
  const text = guard.describeCspscriptsrcGuard(result);
  assert.ok(text.includes('CSPSRC_FLAG_OFF'));
  assert.ok(text.length > 'cspscriptsrcguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspscriptsrcGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspscriptsrcGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
