'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./defaultappclaimguard.js');

const evaluate = mod.evaluateDefaultAppClaimGuard;
const describe = mod.describeDefaultAppClaimGuard;

test('defaultappclaimguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('defaultappclaimguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('defaultappclaimguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('defaultappclaimguard clean snapshot produces no findings', () => {
  const clean = {
  "claimed": [
    "https",
    "mailto"
  ],
  "allowsBroadClaim": false,
  "maxClaims": 3
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('defaultappclaimguard flags CLAIM_SCHEME_UNKNOWN', () => {
  const snapshot = {
  "claimed": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLAIM_SCHEME_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('defaultappclaimguard flags CLAIM_BROAD_RISK', () => {
  const snapshot = {
  "allowsBroadClaim": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLAIM_BROAD_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('defaultappclaimguard flags CLAIM_LIMIT', () => {
  const snapshot = {
  "claimed": [
    "ok0",
    "ok1",
    "ok2",
    "ok3"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLAIM_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('defaultappclaimguard flags CLAIM_EMPTY', () => {
  const snapshot = {
  "claimed": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLAIM_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('defaultappclaimguard describe renders findings in order', () => {
  const snapshot = {"claimed": ["zzz-unknown"]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('defaultappclaimguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
