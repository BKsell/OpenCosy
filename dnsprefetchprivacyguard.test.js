'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./dnsprefetchprivacyguard.js');

const evaluate = mod.evaluateDnsPrefetchPrivacyGuard;
const describe = mod.describeDnsPrefetchPrivacyGuard;

test('dnsprefetchprivacyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('dnsprefetchprivacyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('dnsprefetchprivacyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('dnsprefetchprivacyguard clean snapshot produces no findings', () => {
  const clean = {
  "dnsPrefetch": false,
  "httpsOnly": true,
  "hosts": [
    "example.com"
  ],
  "maxHosts": 50
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('dnsprefetchprivacyguard flags DNS_PREFETCH_RISK', () => {
  const snapshot = {
  "dnsPrefetch": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DNS_PREFETCH_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('dnsprefetchprivacyguard flags DNS_HTTPS_ONLY_OFF', () => {
  const snapshot = {
  "httpsOnly": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DNS_HTTPS_ONLY_OFF);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('dnsprefetchprivacyguard flags DNS_HOST_WILDCARD', () => {
  const snapshot = {
  "hosts": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DNS_HOST_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('dnsprefetchprivacyguard flags DNS_HOST_LIMIT', () => {
  const snapshot = {
  "hosts": [
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
    "ok20",
    "ok21",
    "ok22",
    "ok23",
    "ok24",
    "ok25",
    "ok26",
    "ok27",
    "ok28",
    "ok29",
    "ok30",
    "ok31",
    "ok32",
    "ok33",
    "ok34",
    "ok35",
    "ok36",
    "ok37",
    "ok38",
    "ok39",
    "ok40",
    "ok41",
    "ok42",
    "ok43",
    "ok44",
    "ok45",
    "ok46",
    "ok47",
    "ok48",
    "ok49",
    "ok50"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DNS_HOST_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('dnsprefetchprivacyguard flags DNS_HOST_TRAVERSAL', () => {
  const snapshot = {
  "hosts": [
    "../x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DNS_HOST_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('dnsprefetchprivacyguard describe renders findings in order', () => {
  const snapshot = {"dnsPrefetch": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('dnsprefetchprivacyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
