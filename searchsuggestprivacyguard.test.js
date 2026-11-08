'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./searchsuggestprivacyguard.js');

const evaluate = mod.evaluateSearchSuggestPrivacyGuard;
const describe = mod.describeSearchSuggestPrivacyGuard;

test('searchsuggestprivacyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('searchsuggestprivacyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('searchsuggestprivacyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('searchsuggestprivacyguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": true,
  "endpoint": "https://suggest.example.com/q",
  "hosts": [
    "suggest.example.com"
  ],
  "leakQuery": false
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('searchsuggestprivacyguard flags SUGGEST_ENDPOINT_NOT_HTTPS', () => {
  const snapshot = {
  "endpoint": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SUGGEST_ENDPOINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('searchsuggestprivacyguard flags SUGGEST_ENDPOINT_CREDENTIALS', () => {
  const snapshot = {
  "endpoint": "https://user:pw@evil.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SUGGEST_ENDPOINT_CREDENTIALS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('searchsuggestprivacyguard flags SUGGEST_LEAK_RISK', () => {
  const snapshot = {
  "leakQuery": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SUGGEST_LEAK_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('searchsuggestprivacyguard flags SUGGEST_HOST_LIMIT', () => {
  const snapshot = {
  "hosts": [
    "ok0",
    "ok1",
    "ok2",
    "ok3"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SUGGEST_HOST_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('searchsuggestprivacyguard describe renders findings in order', () => {
  const snapshot = {"endpoint": "http://insecure.test/x"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('searchsuggestprivacyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
