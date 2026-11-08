'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./localfileaccessguard.js');

const evaluate = mod.evaluateLocalFileAccessGuard;
const describe = mod.describeLocalFileAccessGuard;

test('localfileaccessguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('localfileaccessguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('localfileaccessguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('localfileaccessguard clean snapshot produces no findings', () => {
  const clean = {
  "roots": [
    "/home/user/Documents"
  ],
  "allowFileScheme": false,
  "allowAll": false,
  "url": "file:///home/user/a.txt"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('localfileaccessguard flags LOCALFILE_ALLOW_ALL', () => {
  const snapshot = {
  "allowAll": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCALFILE_ALLOW_ALL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('localfileaccessguard flags LOCALFILE_SCHEME', () => {
  const snapshot = {
  "allowFileScheme": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCALFILE_SCHEME);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('localfileaccessguard flags LOCALFILE_ROOT_TRAVERSAL', () => {
  const snapshot = {
  "roots": [
    "../x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCALFILE_ROOT_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('localfileaccessguard flags LOCALFILE_ROOT_LIMIT', () => {
  const snapshot = {
  "roots": [
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
    "ok10"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCALFILE_ROOT_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('localfileaccessguard flags LOCALFILE_URL_TRAVERSAL', () => {
  const snapshot = {
  "url": ".."
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.LOCALFILE_URL_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('localfileaccessguard describe renders findings in order', () => {
  const snapshot = {"allowAll": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('localfileaccessguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
