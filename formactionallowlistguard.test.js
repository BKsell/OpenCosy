'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./formactionallowlistguard.js');

const REASONS = ["FRMACT_FLAG_OFF", "FRMACT_REPORT_ONLY", "FRMACT_MODE_INVALID", "FRMACT_COUNT_OUT_OF_RANGE", "FRMACT_ENDPOINT_INSECURE", "FRMACT_ENDPOINT_TOO_LONG", "FRMACT_NOTE_CONTROL", "FRMACT_PATH_TRAVERSAL", "FRMACT_ITEM_UNKNOWN", "FRMACT_ITEM_DUPLICATE", "FRMACT_ITEM_COUNT", "FRMACT_BASELINE_EMPTY"];
const CLEAN = {
  "formAction": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 600,
    "endpoint": "https://form.example.com/submit",
    "note": "form-note",
    "storagePath": "policies/form",
    "items": [
      "https://form.example.com"
    ],
    "baseline": [
      "form"
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
  assert.strictEqual(typeof guard.evaluateFormactionallowlistGuard, 'function');
  assert.strictEqual(typeof guard.describeFormactionallowlistGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateFormactionallowlistGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateFormactionallowlistGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule FRMACT_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.enabled', false));
  assert.ok(hasKey(result, 'FRMACT_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule FRMACT_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.reportOnly', true));
  assert.ok(hasKey(result, 'FRMACT_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.mode', "bogus-value"));
  assert.ok(hasKey(result, 'FRMACT_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule FRMACT_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.lifetime', 179));
  assert.ok(hasKey(result, 'FRMACT_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'FRMACT_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule FRMACT_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'FRMACT_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.note', "a\u0007b"));
  assert.ok(hasKey(result, 'FRMACT_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'FRMACT_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule FRMACT_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'FRMACT_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule FRMACT_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'FRMACT_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'FRMACT_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule FRMACT_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.baseline', []));
  assert.ok(hasKey(result, 'FRMACT_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'FRMACT_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateFormactionallowlistGuard(withValue('formAction.enabled', false));
  const text = guard.describeFormactionallowlistGuard(result);
  assert.ok(text.includes('FRMACT_FLAG_OFF'));
  assert.ok(text.length > 'formactionallowlistguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeFormactionallowlistGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateFormactionallowlistGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
