'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./crashrecoveryguard.js');

const evaluate = mod.evaluateCrashRecoveryGuard;
const describe = mod.describeCrashRecoveryGuard;

test('crashrecoveryguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('crashrecoveryguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('crashrecoveryguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('crashrecoveryguard clean snapshot produces no findings', () => {
  const clean = {
  "uploadReports": false,
  "endpoint": "https://example.com/crash",
  "retentionDays": 7,
  "hosts": [
    "example.com"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('crashrecoveryguard flags CRASH_UPLOAD_RISK', () => {
  const snapshot = {
  "uploadReports": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CRASH_UPLOAD_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('crashrecoveryguard flags CRASH_ENDPOINT_NOT_HTTPS', () => {
  const snapshot = {
  "endpoint": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CRASH_ENDPOINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crashrecoveryguard flags CRASH_RETENTION_RANGE', () => {
  const snapshot = {
  "retentionDays": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CRASH_RETENTION_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('crashrecoveryguard flags CRASH_ENDPOINT_CREDENTIALS', () => {
  const snapshot = {
  "endpoint": "https://user:pw@evil.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CRASH_ENDPOINT_CREDENTIALS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crashrecoveryguard describe renders findings in order', () => {
  const snapshot = {"uploadReports": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('crashrecoveryguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
