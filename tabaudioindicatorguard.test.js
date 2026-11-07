'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./tabaudioindicatorguard.js');

const evaluate = mod.evaluateTabAudioIndicatorGuard;
const describe = mod.describeTabAudioIndicatorGuard;

test('tabaudioindicatorguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('tabaudioindicatorguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('tabaudioindicatorguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('tabaudioindicatorguard clean snapshot produces no findings', () => {
  const clean = {
  "tabs": [
    {
      "id": "t1",
      "audible": false,
      "muted": false
    }
  ],
  "showIndicator": true
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('tabaudioindicatorguard flags TAB_AUDIO_INDICATOR_OFF', () => {
  const snapshot = {
  "showIndicator": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TAB_AUDIO_INDICATOR_OFF);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabaudioindicatorguard flags TAB_AUDIO_MISSING_ID', () => {
  const snapshot = {
  "tabs": [
    {}
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TAB_AUDIO_MISSING_ID);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('tabaudioindicatorguard flags TAB_AUDIO_DUPLICATE_ID', () => {
  const snapshot = {
  "tabs": [
    {
      "id": "dup"
    },
    {
      "id": "dup"
    }
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TAB_AUDIO_DUPLICATE_ID);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('tabaudioindicatorguard flags TAB_AUDIO_STATE_MISMATCH', () => {
  const snapshot = {
  "stateMismatch": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TAB_AUDIO_STATE_MISMATCH);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabaudioindicatorguard flags TAB_AUDIO_LIMIT', () => {
  const snapshot = {
  "tabs": [
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
    "ok64"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.TAB_AUDIO_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('tabaudioindicatorguard describe renders findings in order', () => {
  const snapshot = {"showIndicator": false};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('tabaudioindicatorguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
