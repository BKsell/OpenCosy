'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./safebrowsingguard.js');

const evaluate = mod.evaluateSafeBrowsingGuard;
const describe = mod.describeSafeBrowsingGuard;

test('safebrowsingguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('safebrowsingguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('safebrowsingguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('safebrowsingguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": true,
  "provider": "local",
  "updateIntervalHours": 6,
  "endpoint": "https://example.com/sb"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('safebrowsingguard flags SAFE_PROVIDER_UNKNOWN', () => {
  const snapshot = {
  "provider": "zzz-unknown"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SAFE_PROVIDER_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('safebrowsingguard flags SAFE_INTERVAL_RANGE', () => {
  const snapshot = {
  "updateIntervalHours": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SAFE_INTERVAL_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('safebrowsingguard flags SAFE_ENDPOINT_NOT_HTTPS', () => {
  const snapshot = {
  "endpoint": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SAFE_ENDPOINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('safebrowsingguard flags SAFE_DISABLED', () => {
  const snapshot = {
  "enabled": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SAFE_DISABLED);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('safebrowsingguard describe renders findings in order', () => {
  const snapshot = {"provider": "zzz-unknown"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('safebrowsingguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
