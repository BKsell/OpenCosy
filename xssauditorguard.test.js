'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./xssauditorguard.js');

const REASONS = ["XSSAUD_FLAG_OFF", "XSSAUD_REPORT_ONLY", "XSSAUD_MODE_INVALID", "XSSAUD_COUNT_OUT_OF_RANGE", "XSSAUD_ENDPOINT_INSECURE", "XSSAUD_ENDPOINT_TOO_LONG", "XSSAUD_NOTE_CONTROL", "XSSAUD_PATH_TRAVERSAL", "XSSAUD_ITEM_UNKNOWN", "XSSAUD_ITEM_DUPLICATE", "XSSAUD_ITEM_COUNT", "XSSAUD_BASELINE_EMPTY"];
const CLEAN = {
  "xssAuditor": {
    "enabled": true,
    "reportOnly": false,
    "mode": "enabled",
    "lifetime": 300,
    "endpoint": "https://xss.example.com/filter",
    "note": "xss-note",
    "storagePath": "policies/xss",
    "items": [
      "mode-block"
    ],
    "baseline": [
      "xss"
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
  assert.strictEqual(typeof guard.evaluateXssauditorGuard, 'function');
  assert.strictEqual(typeof guard.describeXssauditorGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateXssauditorGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateXssauditorGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule XSSAUD_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.enabled', false));
  assert.ok(hasKey(result, 'XSSAUD_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule XSSAUD_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.reportOnly', true));
  assert.ok(hasKey(result, 'XSSAUD_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.mode', "bogus-value"));
  assert.ok(hasKey(result, 'XSSAUD_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule XSSAUD_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.lifetime', 59));
  assert.ok(hasKey(result, 'XSSAUD_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'XSSAUD_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule XSSAUD_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'XSSAUD_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.note', "a\u0007b"));
  assert.ok(hasKey(result, 'XSSAUD_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'XSSAUD_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule XSSAUD_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'XSSAUD_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule XSSAUD_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'XSSAUD_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'XSSAUD_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule XSSAUD_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.baseline', []));
  assert.ok(hasKey(result, 'XSSAUD_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'XSSAUD_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateXssauditorGuard(withValue('xssAuditor.enabled', false));
  const text = guard.describeXssauditorGuard(result);
  assert.ok(text.includes('XSSAUD_FLAG_OFF'));
  assert.ok(text.length > 'xssauditorguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeXssauditorGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateXssauditorGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
