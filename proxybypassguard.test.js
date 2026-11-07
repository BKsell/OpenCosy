'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./proxybypassguard.js');

const evaluate = mod.evaluateProxyBypassGuard;
const describe = mod.describeProxyBypassGuard;

test('proxybypassguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('proxybypassguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('proxybypassguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('proxybypassguard clean snapshot produces no findings', () => {
  const clean = {
  "proxy": "https://proxy.example.com:8443",
  "bypass": [
    "localhost"
  ],
  "maxBypass": 20
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('proxybypassguard flags PROXY_NOT_HTTPS', () => {
  const snapshot = {
  "proxy": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROXY_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('proxybypassguard flags PROXY_CREDENTIALS_IN_URL', () => {
  const snapshot = {
  "proxy": "https://user:pw@evil.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROXY_CREDENTIALS_IN_URL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('proxybypassguard flags PROXY_BYPASS_WILDCARD', () => {
  const snapshot = {
  "bypass": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROXY_BYPASS_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('proxybypassguard flags PROXY_BYPASS_LIMIT', () => {
  const snapshot = {
  "bypass": [
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
    "ok12",
    "ok13",
    "ok14",
    "ok15",
    "ok16",
    "ok17",
    "ok18",
    "ok19",
    "ok20"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROXY_BYPASS_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('proxybypassguard flags PROXY_BYPASS_EMPTY', () => {
  const snapshot = {
  "bypass": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROXY_BYPASS_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('proxybypassguard describe renders findings in order', () => {
  const snapshot = {"proxy": "http://insecure.test/x"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('proxybypassguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
