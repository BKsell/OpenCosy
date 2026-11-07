'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./passwordrevealguard.js');

const evaluate = mod.evaluatePasswordRevealGuard;
const describe = mod.describePasswordRevealGuard;

test('passwordrevealguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('passwordrevealguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('passwordrevealguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('passwordrevealguard clean snapshot produces no findings', () => {
  const clean = {
  "revealEnabled": false,
  "revealSeconds": 5,
  "perSitePermissions": 2
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('passwordrevealguard flags REVEAL_ENABLED_RISK', () => {
  const snapshot = {
  "revealEnabled": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REVEAL_ENABLED_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('passwordrevealguard flags REVEAL_SECONDS_RANGE', () => {
  const snapshot = {
  "revealSeconds": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REVEAL_SECONDS_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('passwordrevealguard flags REVEAL_SITE_LIMIT', () => {
  const snapshot = {
  "perSitePermissions": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.REVEAL_SITE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('passwordrevealguard describe renders findings in order', () => {
  const snapshot = {"revealEnabled": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('passwordrevealguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
