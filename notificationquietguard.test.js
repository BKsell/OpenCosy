'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./notificationquietguard.js');

const evaluate = mod.evaluateNotificationQuietGuard;
const describe = mod.describeNotificationQuietGuard;

test('notificationquietguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('notificationquietguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('notificationquietguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('notificationquietguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": true,
  "startHour": 22,
  "endHour": 7,
  "overrideDnd": false
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('notificationquietguard flags QUIET_HOUR_RANGE', () => {
  const snapshot = {
  "startHour": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.QUIET_HOUR_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('notificationquietguard flags QUIET_HOUR_END_RANGE', () => {
  const snapshot = {
  "endHour": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.QUIET_HOUR_END_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('notificationquietguard flags QUIET_OVERRIDE_RISK', () => {
  const snapshot = {
  "overrideDnd": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.QUIET_OVERRIDE_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('notificationquietguard flags QUIET_DISABLED', () => {
  const snapshot = {
  "enabled": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.QUIET_DISABLED);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('notificationquietguard describe renders findings in order', () => {
  const snapshot = {"startHour": -1};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('notificationquietguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
