'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./dnsleakpreventionguard.js');

const REASONS = ["DNSLEAK_FLAG_OFF", "DNSLEAK_REPORT_ONLY", "DNSLEAK_MODE_INVALID", "DNSLEAK_COUNT_OUT_OF_RANGE", "DNSLEAK_ENDPOINT_INSECURE", "DNSLEAK_ENDPOINT_TOO_LONG", "DNSLEAK_NOTE_CONTROL", "DNSLEAK_PATH_TRAVERSAL", "DNSLEAK_ITEM_UNKNOWN", "DNSLEAK_ITEM_DUPLICATE", "DNSLEAK_ITEM_COUNT", "DNSLEAK_BASELINE_EMPTY"];
const CLEAN = {
  "dnsLeak": {
    "enabled": true,
    "reportOnly": false,
    "mode": "strict",
    "lifetime": 900,
    "endpoint": "https://dns.example.com/resolve",
    "note": "dns-note",
    "storagePath": "policies/dns",
    "items": [
      "proxy-dns"
    ],
    "baseline": [
      "dns"
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
  assert.strictEqual(typeof guard.evaluateDnsleakpreventionGuard, 'function');
  assert.strictEqual(typeof guard.describeDnsleakpreventionGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluateDnsleakpreventionGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluateDnsleakpreventionGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule DNSLEAK_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.enabled', false));
  assert.ok(hasKey(result, 'DNSLEAK_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule DNSLEAK_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.reportOnly', true));
  assert.ok(hasKey(result, 'DNSLEAK_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.mode', "bogus-value"));
  assert.ok(hasKey(result, 'DNSLEAK_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule DNSLEAK_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.lifetime', 299));
  assert.ok(hasKey(result, 'DNSLEAK_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'DNSLEAK_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule DNSLEAK_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'DNSLEAK_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.note', "a\u0007b"));
  assert.ok(hasKey(result, 'DNSLEAK_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'DNSLEAK_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule DNSLEAK_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'DNSLEAK_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule DNSLEAK_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'DNSLEAK_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'DNSLEAK_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule DNSLEAK_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.baseline', []));
  assert.ok(hasKey(result, 'DNSLEAK_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'DNSLEAK_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluateDnsleakpreventionGuard(withValue('dnsLeak.enabled', false));
  const text = guard.describeDnsleakpreventionGuard(result);
  assert.ok(text.includes('DNSLEAK_FLAG_OFF'));
  assert.ok(text.length > 'dnsleakpreventionguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describeDnsleakpreventionGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluateDnsleakpreventionGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
