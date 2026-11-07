'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./extensionpermissionguard.js');

const evaluate = mod.evaluateExtensionPermissionGuard;
const describe = mod.describeExtensionPermissionGuard;

test('extensionpermissionguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('extensionpermissionguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('extensionpermissionguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('extensionpermissionguard clean snapshot produces no findings', () => {
  const clean = {
  "permissions": [
    "storage"
  ],
  "hosts": [
    "https://example.com"
  ],
  "dangerous": [
    "tabs",
    "cookies"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('extensionpermissionguard flags EXTENSION_PERM_UNKNOWN', () => {
  const snapshot = {
  "permissions": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.EXTENSION_PERM_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('extensionpermissionguard flags EXTENSION_PERM_DANGEROUS', () => {
  const snapshot = {
  "permissions": [
    "nativeMessaging"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.EXTENSION_PERM_DANGEROUS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('extensionpermissionguard flags EXTENSION_HOST_WILDCARD', () => {
  const snapshot = {
  "hosts": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.EXTENSION_HOST_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('extensionpermissionguard flags EXTENSION_PERM_LIMIT', () => {
  const snapshot = {
  "permissions": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4",
    "ok5",
    "ok6",
    "ok7",
    "ok8",
    "ok9",
    "ok10",
    "ok11",
    "ok12"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.EXTENSION_PERM_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('extensionpermissionguard describe renders findings in order', () => {
  const snapshot = {"permissions": ["zzz-unknown"]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('extensionpermissionguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
