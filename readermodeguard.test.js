'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./readermodeguard.js');

const evaluate = mod.evaluateReaderModeGuard;
const describe = mod.describeReaderModeGuard;

test('readermodeguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('readermodeguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('readermodeguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('readermodeguard clean snapshot produces no findings', () => {
  const clean = {
  "autoEnable": false,
  "hosts": [
    "example.com"
  ],
  "maxWidth": 720
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('readermodeguard flags READER_AUTO_RISK', () => {
  const snapshot = {
  "autoEnable": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.READER_AUTO_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('readermodeguard flags READER_HOST_WILDCARD', () => {
  const snapshot = {
  "hosts": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.READER_HOST_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('readermodeguard flags READER_HOST_TRAVERSAL', () => {
  const snapshot = {
  "hosts": [
    "../x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.READER_HOST_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('readermodeguard flags READER_HOST_LIMIT', () => {
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
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.READER_HOST_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('readermodeguard flags READER_WIDTH_RANGE', () => {
  const snapshot = {
  "maxWidth": 319
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.READER_WIDTH_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('readermodeguard describe renders findings in order', () => {
  const snapshot = {"autoEnable": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('readermodeguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
