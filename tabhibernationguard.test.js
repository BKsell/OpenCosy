'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./tabhibernationguard.js');

const evaluate = mod.evaluateTabHibernationGuard;
const describe = mod.describeTabHibernationGuard;

test('tabhibernationguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('tabhibernationguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('tabhibernationguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('tabhibernationguard clean snapshot produces no findings', () => {
  const clean = {
  "timeoutMinutes": 30,
  "maxHibernated": 60,
  "aggressive": false,
  "exemptHosts": [
    "example.com"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('tabhibernationguard flags HIBERNATE_TIMEOUT_RANGE', () => {
  const snapshot = {
  "timeoutMinutes": 4
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HIBERNATE_TIMEOUT_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabhibernationguard flags HIBERNATE_LIMIT_RANGE', () => {
  const snapshot = {
  "maxHibernated": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HIBERNATE_LIMIT_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabhibernationguard flags HIBERNATE_AGGRESSIVE_RISK', () => {
  const snapshot = {
  "aggressive": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HIBERNATE_AGGRESSIVE_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabhibernationguard flags HIBERNATE_EXEMPT_WILDCARD', () => {
  const snapshot = {
  "exemptHosts": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HIBERNATE_EXEMPT_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('tabhibernationguard flags HIBERNATE_EXEMPT_LIMIT', () => {
  const snapshot = {
  "exemptHosts": [
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
    "ok50",
    "ok51",
    "ok52",
    "ok53",
    "ok54",
    "ok55",
    "ok56",
    "ok57",
    "ok58",
    "ok59",
    "ok60",
    "ok61",
    "ok62",
    "ok63",
    "ok64",
    "ok65",
    "ok66",
    "ok67",
    "ok68",
    "ok69",
    "ok70",
    "ok71",
    "ok72",
    "ok73",
    "ok74",
    "ok75",
    "ok76",
    "ok77",
    "ok78",
    "ok79",
    "ok80",
    "ok81",
    "ok82",
    "ok83",
    "ok84",
    "ok85",
    "ok86",
    "ok87",
    "ok88",
    "ok89",
    "ok90",
    "ok91",
    "ok92",
    "ok93",
    "ok94",
    "ok95",
    "ok96",
    "ok97",
    "ok98",
    "ok99",
    "ok100"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HIBERNATE_EXEMPT_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabhibernationguard describe renders findings in order', () => {
  const snapshot = {"timeoutMinutes": 4};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('tabhibernationguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
