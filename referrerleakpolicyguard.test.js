'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./referrerleakpolicyguard.js');

const evaluate = mod.evaluateReferrerLeakPolicyGuard;
const describe = mod.describeReferrerLeakPolicyGuard;

test('referrerleakpolicyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('referrerleakpolicyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('referrerleakpolicyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('referrerleakpolicyguard clean snapshot produces no findings', () => {
  const clean = {
  "policy": "strict-origin-when-cross-origin",
  "downgrade": false,
  "trimCrossOrigin": true
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('referrerleakpolicyguard flags REFERRER_POLICY_UNKNOWN', () => {
  const snapshot = {
  "policy": "zzz-unknown"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REFERRER_POLICY_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('referrerleakpolicyguard flags REFERRER_UPGRADE_DOWNGRADE', () => {
  const snapshot = {
  "downgrade": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REFERRER_UPGRADE_DOWNGRADE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('referrerleakpolicyguard flags REFERRER_FULL_CROSS_ORIGIN', () => {
  const snapshot = {
  "trimCrossOrigin": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REFERRER_FULL_CROSS_ORIGIN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('referrerleakpolicyguard flags REFERRER_POLICY_TOO_LONG', () => {
  const snapshot = {
  "policy": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REFERRER_POLICY_TOO_LONG);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('referrerleakpolicyguard describe renders findings in order', () => {
  const snapshot = {"policy": "zzz-unknown"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('referrerleakpolicyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
