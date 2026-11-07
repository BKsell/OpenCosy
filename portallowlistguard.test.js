'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./portallowlistguard.js');

const REASONS = ["PORTALW_FLAG_OFF", "PORTALW_REPORT_ONLY", "PORTALW_MODE_INVALID", "PORTALW_COUNT_OUT_OF_RANGE", "PORTALW_ENDPOINT_INSECURE", "PORTALW_ENDPOINT_TOO_LONG", "PORTALW_NOTE_CONTROL", "PORTALW_PATH_TRAVERSAL", "PORTALW_ITEM_UNKNOWN", "PORTALW_ITEM_DUPLICATE", "PORTALW_ITEM_COUNT", "PORTALW_BASELINE_EMPTY"];
const CLEAN = {
  "portAllow": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 600,
    "endpoint": "https://port.example.com/service",
    "note": "port-note",
    "storagePath": "policies/port",
    "items": [
      "443"
    ],
    "baseline": [
      "port"
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
  assert.strictEqual(typeof guard.evaluatePortallowlistGuard, 'function');
  assert.strictEqual(typeof guard.describePortallowlistGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePortallowlistGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePortallowlistGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PORTALW_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.enabled', false));
  assert.ok(hasKey(result, 'PORTALW_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PORTALW_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.reportOnly', true));
  assert.ok(hasKey(result, 'PORTALW_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PORTALW_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PORTALW_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.lifetime', 179));
  assert.ok(hasKey(result, 'PORTALW_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PORTALW_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PORTALW_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PORTALW_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PORTALW_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PORTALW_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PORTALW_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PORTALW_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PORTALW_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PORTALW_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PORTALW_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PORTALW_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.baseline', []));
  assert.ok(hasKey(result, 'PORTALW_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PORTALW_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePortallowlistGuard(withValue('portAllow.enabled', false));
  const text = guard.describePortallowlistGuard(result);
  assert.ok(text.includes('PORTALW_FLAG_OFF'));
  assert.ok(text.length > 'portallowlistguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePortallowlistGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePortallowlistGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
