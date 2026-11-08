'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./webextensionupdateguard.js');

const evaluate = mod.evaluateWebExtensionUpdateGuard;
const describe = mod.describeWebExtensionUpdateGuard;

test('webextensionupdateguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('webextensionupdateguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('webextensionupdateguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('webextensionupdateguard clean snapshot produces no findings', () => {
  const clean = {
  "updateUrl": "https://updates.example.com/manifest.json",
  "autoUpdate": false,
  "hosts": [
    "updates.example.com"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('webextensionupdateguard flags UPDATE_URL_NOT_HTTPS', () => {
  const snapshot = {
  "updateUrl": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.UPDATE_URL_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('webextensionupdateguard flags UPDATE_AUTO_RISK', () => {
  const snapshot = {
  "autoUpdate": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.UPDATE_AUTO_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('webextensionupdateguard flags UPDATE_URL_CREDENTIALS', () => {
  const snapshot = {
  "updateUrl": "https://user:pw@evil.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.UPDATE_URL_CREDENTIALS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('webextensionupdateguard flags UPDATE_HOST_LIMIT', () => {
  const snapshot = {
  "hosts": [
    "ok0",
    "ok1",
    "ok2",
    "ok3"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.UPDATE_HOST_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('webextensionupdateguard describe renders findings in order', () => {
  const snapshot = {"updateUrl": "http://insecure.test/x"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('webextensionupdateguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
