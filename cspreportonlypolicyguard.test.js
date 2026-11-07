'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./cspreportonlypolicyguard.js');

const evaluate = mod.evaluateCspReportOnlyPolicyGuard;
const describe = mod.describeCspReportOnlyPolicyGuard;

test('cspreportonlypolicyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('cspreportonlypolicyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('cspreportonlypolicyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('cspreportonlypolicyguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "content-security-policy-report-only": "default-src 'self'; report-to csp"
  },
  "reportTo": "csp",
  "endpoint": "https://example.com/csp"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('cspreportonlypolicyguard flags CSPRO_MISSING', () => {
  const snapshot = {
  "headers": {
    "content-security-policy-report-only": ""
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CSPRO_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('cspreportonlypolicyguard flags CSPRO_UNSAFE_INLINE', () => {
  const snapshot = {
  "headers": {
    "content-security-policy-report-only": "default-src 'unsafe-inline'"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CSPRO_UNSAFE_INLINE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('cspreportonlypolicyguard flags CSPRO_ENDPOINT_NOT_HTTPS', () => {
  const snapshot = {
  "endpoint": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CSPRO_ENDPOINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('cspreportonlypolicyguard flags CSPRO_GROUP_MISMATCH', () => {
  const snapshot = {
  "headers": {
    "content-security-policy-report-only": "default-src self; report-to other-group"
  },
  "reportTo": "csp"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CSPRO_GROUP_MISMATCH);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('cspreportonlypolicyguard flags CSPRO_ENDPOINT_LIMIT', () => {
  const snapshot = {
  "endpointCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CSPRO_ENDPOINT_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('cspreportonlypolicyguard describe renders findings in order', () => {
  const snapshot = {"headers": {"content-security-policy-report-only": ""}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('cspreportonlypolicyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
