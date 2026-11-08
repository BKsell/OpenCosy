'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./sessionlockguard.js');

const evaluate = mod.evaluateSessionLockGuard;
const describe = mod.describeSessionLockGuard;

test('sessionlockguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('sessionlockguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('sessionlockguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('sessionlockguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": true,
  "idleMinutes": 15,
  "lockOnMinimize": true,
  "unlock": "password"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('sessionlockguard flags LOCK_IDLE_RANGE', () => {
  const snapshot = {
  "idleMinutes": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCK_IDLE_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sessionlockguard flags LOCK_UNLOCK_UNKNOWN', () => {
  const snapshot = {
  "unlock": "zzz-unknown"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCK_UNLOCK_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('sessionlockguard flags LOCK_DISABLED', () => {
  const snapshot = {
  "enabled": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCK_DISABLED);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sessionlockguard flags LOCK_MINIMIZE_OFF', () => {
  const snapshot = {
  "lockOnMinimize": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCK_MINIMIZE_OFF);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sessionlockguard describe renders findings in order', () => {
  const snapshot = {"idleMinutes": 0};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('sessionlockguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
