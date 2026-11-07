'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./trustedtypesguard.js');

const evaluate = mod.evaluateTrustedTypesGuard;
const describe = mod.describeTrustedTypesGuard;

test('trustedtypesguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('trustedtypesguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('trustedtypesguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('trustedtypesguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "content-security-policy": "require-trusted-types-for 'script'; trusted-types default"
  }
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('trustedtypesguard flags TT_MISSING_FOR', () => {
  const snapshot = {
  "headers": {
    "content-security-policy": "*"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TT_MISSING_FOR);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('trustedtypesguard flags TT_MISSING_POLICIES', () => {
  const snapshot = {
  "headers": {
    "content-security-policy": "*"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TT_MISSING_POLICIES);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('trustedtypesguard flags TT_WILDCARD', () => {
  const snapshot = {
  "headers": {
    "content-security-policy": "trusted-types *"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TT_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('trustedtypesguard flags TT_POLICY_LIMIT', () => {
  const snapshot = {
  "policyCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TT_POLICY_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('trustedtypesguard describe renders findings in order', () => {
  const snapshot = {"headers": {"content-security-policy": "*"}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('trustedtypesguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
