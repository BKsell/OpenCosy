'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./autocompleteoffguard.js');

const REASONS = ["AUTOCMP_FLAG_OFF", "AUTOCMP_REPORT_ONLY", "AUTOCMP_MODE_INVALID", "AUTOCMP_COUNT_OUT_OF_RANGE", "AUTOCMP_ENDPOINT_INSECURE", "AUTOCMP_ENDPOINT_TOO_LONG", "AUTOCMP_NOTE_CONTROL", "AUTOCMP_PATH_TRAVERSAL", "AUTOCMP_ITEM_UNKNOWN", "AUTOCMP_ITEM_DUPLICATE", "AUTOCMP_ITEM_COUNT", "AUTOCMP_BASELINE_EMPTY"];
const CLEAN = {
  "autocomplete": {
    "enabled": true,
    "reportOnly": false,
    "mode": "off",
    "lifetime": 300,
    "endpoint": "https://autofill.example.com/field",
    "note": "autofill-note",
    "storagePath": "policies/autofill",
    "items": [
      "off"
    ],
    "baseline": [
      "autofill"
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
  assert.strictEqual(typeof guard.evaluateAutocompleteoffGuard, 'function');
  assert.strictEqual(typeof guard.describeAutocompleteoffGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateAutocompleteoffGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateAutocompleteoffGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule AUTOCMP_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.enabled', false));
  assert.ok(hasKey(result, 'AUTOCMP_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule AUTOCMP_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.reportOnly', true));
  assert.ok(hasKey(result, 'AUTOCMP_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.mode', "bogus-value"));
  assert.ok(hasKey(result, 'AUTOCMP_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule AUTOCMP_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.lifetime', 59));
  assert.ok(hasKey(result, 'AUTOCMP_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'AUTOCMP_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule AUTOCMP_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'AUTOCMP_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.note', "a\u0007b"));
  assert.ok(hasKey(result, 'AUTOCMP_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'AUTOCMP_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule AUTOCMP_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'AUTOCMP_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule AUTOCMP_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'AUTOCMP_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'AUTOCMP_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule AUTOCMP_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.baseline', []));
  assert.ok(hasKey(result, 'AUTOCMP_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'AUTOCMP_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateAutocompleteoffGuard(withValue('autocomplete.enabled', false));
  const text = guard.describeAutocompleteoffGuard(result);
  assert.ok(text.includes('AUTOCMP_FLAG_OFF'));
  assert.ok(text.length > 'autocompleteoffguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeAutocompleteoffGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateAutocompleteoffGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
