'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./securecontextguard.js');

const REASONS = ["SECCTX_FLAG_OFF", "SECCTX_REPORT_ONLY", "SECCTX_MODE_INVALID", "SECCTX_COUNT_OUT_OF_RANGE", "SECCTX_ENDPOINT_INSECURE", "SECCTX_ENDPOINT_TOO_LONG", "SECCTX_NOTE_CONTROL", "SECCTX_PATH_TRAVERSAL", "SECCTX_ITEM_UNKNOWN", "SECCTX_ITEM_DUPLICATE", "SECCTX_ITEM_COUNT", "SECCTX_BASELINE_EMPTY"];
const CLEAN = {
  "secureContext": {
    "enabled": true,
    "reportOnly": false,
    "mode": "required",
    "lifetime": 600,
    "endpoint": "https://context.example.com/secure",
    "note": "context-note",
    "storagePath": "policies/context",
    "items": [
      "isSecureContext"
    ],
    "baseline": [
      "context"
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
  assert.strictEqual(typeof guard.evaluateSecurecontextGuard, 'function');
  assert.strictEqual(typeof guard.describeSecurecontextGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateSecurecontextGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateSecurecontextGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule SECCTX_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.enabled', false));
  assert.ok(hasKey(result, 'SECCTX_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule SECCTX_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.reportOnly', true));
  assert.ok(hasKey(result, 'SECCTX_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.mode', "bogus-value"));
  assert.ok(hasKey(result, 'SECCTX_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule SECCTX_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.lifetime', 179));
  assert.ok(hasKey(result, 'SECCTX_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'SECCTX_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule SECCTX_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'SECCTX_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.note', "a\u0007b"));
  assert.ok(hasKey(result, 'SECCTX_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'SECCTX_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule SECCTX_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'SECCTX_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule SECCTX_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'SECCTX_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.items', ["filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'SECCTX_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule SECCTX_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.baseline', []));
  assert.ok(hasKey(result, 'SECCTX_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'SECCTX_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateSecurecontextGuard(withValue('secureContext.enabled', false));
  const text = guard.describeSecurecontextGuard(result);
  assert.ok(text.includes('SECCTX_FLAG_OFF'));
  assert.ok(text.length > 'securecontextguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeSecurecontextGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateSecurecontextGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
