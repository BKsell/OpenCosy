'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./permissionpolicyreportguard.js');

const evaluate = mod.evaluatePermissionPolicyReportGuard;
const describe = mod.describePermissionPolicyReportGuard;

test('permissionpolicyreportguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('permissionpolicyreportguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('permissionpolicyreportguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('permissionpolicyreportguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "permissions-policy": "geolocation=(), camera=()"
  },
  "reportTo": "default",
  "endpoint": "https://example.com/report"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('permissionpolicyreportguard flags PP_REPORT_MISSING', () => {
  const snapshot = {
  "reportTo": ""
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PP_REPORT_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('permissionpolicyreportguard flags PP_ENDPOINT_NOT_HTTPS', () => {
  const snapshot = {
  "endpoint": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PP_ENDPOINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('permissionpolicyreportguard flags PP_ENDPOINT_CREDENTIALS', () => {
  const snapshot = {
  "endpoint": "https://user:pw@evil.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PP_ENDPOINT_CREDENTIALS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('permissionpolicyreportguard flags PP_GROUP_LIMIT', () => {
  const snapshot = {
  "groupCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PP_GROUP_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('permissionpolicyreportguard flags PP_DUPLICATE_GROUP', () => {
  const snapshot = {
  "groups": [
    "dup",
    "dup"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PP_DUPLICATE_GROUP);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('permissionpolicyreportguard describe renders findings in order', () => {
  const snapshot = {"reportTo": ""};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('permissionpolicyreportguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
