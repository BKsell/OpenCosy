'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./cspupgradeinsecurerequestguard.js');

const REASONS = ["CSPUIR_FLAG_OFF", "CSPUIR_REPORT_ONLY", "CSPUIR_MODE_INVALID", "CSPUIR_COUNT_OUT_OF_RANGE", "CSPUIR_ENDPOINT_INSECURE", "CSPUIR_ENDPOINT_TOO_LONG", "CSPUIR_NOTE_CONTROL", "CSPUIR_PATH_TRAVERSAL", "CSPUIR_ITEM_UNKNOWN", "CSPUIR_ITEM_DUPLICATE", "CSPUIR_ITEM_COUNT", "CSPUIR_BASELINE_EMPTY"];
const CLEAN = {
  "csp": {
    "enabled": true,
    "reportOnly": false,
    "mode": "enforce",
    "lifetime": 86400,
    "endpoint": "https://cdn.example.com/policy",
    "note": "policy-a",
    "storagePath": "policies/csp",
    "items": [
      "default-src",
      "script-src"
    ],
    "baseline": [
      "upgrade-insecure-requests"
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
  assert.strictEqual(typeof guard.evaluateCspupgradeinsecurerequestGuard, 'function');
  assert.strictEqual(typeof guard.describeCspupgradeinsecurerequestGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule CSPUIR_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.enabled', false));
  assert.ok(hasKey(result, 'CSPUIR_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPUIR_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.reportOnly', true));
  assert.ok(hasKey(result, 'CSPUIR_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.mode', "bogus-value"));
  assert.ok(hasKey(result, 'CSPUIR_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPUIR_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.lifetime', 3599));
  assert.ok(hasKey(result, 'CSPUIR_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'CSPUIR_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPUIR_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'CSPUIR_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.note', "a\u0007b"));
  assert.ok(hasKey(result, 'CSPUIR_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'CSPUIR_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPUIR_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'CSPUIR_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule CSPUIR_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'CSPUIR_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'CSPUIR_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule CSPUIR_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.baseline', []));
  assert.ok(hasKey(result, 'CSPUIR_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'CSPUIR_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard(withValue('csp.enabled', false));
  const text = guard.describeCspupgradeinsecurerequestGuard(result);
  assert.ok(text.includes('CSPUIR_FLAG_OFF'));
  assert.ok(text.length > 'cspupgradeinsecurerequestguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeCspupgradeinsecurerequestGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateCspupgradeinsecurerequestGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
