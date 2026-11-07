'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./pagezoomguard.js');

const evaluate = mod.evaluatePageZoomGuard;
const describe = mod.describePageZoomGuard;

test('pagezoomguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('pagezoomguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('pagezoomguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('pagezoomguard clean snapshot produces no findings', () => {
  const clean = {
  "zoom": 100,
  "sites": [
    {
      "host": "example.com",
      "zoom": 110
    }
  ],
  "min": 50,
  "max": 300
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('pagezoomguard flags ZOOM_OUT_OF_RANGE', () => {
  const snapshot = {
  "zoom": 49
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_OUT_OF_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pagezoomguard flags ZOOM_SITE_HOST_EMPTY', () => {
  const snapshot = {
  "sites": [
    {}
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_SITE_HOST_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('pagezoomguard flags ZOOM_SITE_WILDCARD', () => {
  const snapshot = {
  "sites": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_SITE_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('pagezoomguard flags ZOOM_SITE_TRAVERSAL', () => {
  const snapshot = {
  "sites": [
    "../x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_SITE_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('pagezoomguard flags ZOOM_SITE_LIMIT', () => {
  const snapshot = {
  "sites": [
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
    "ok100",
    "ok101",
    "ok102",
    "ok103",
    "ok104",
    "ok105",
    "ok106",
    "ok107",
    "ok108",
    "ok109",
    "ok110",
    "ok111",
    "ok112",
    "ok113",
    "ok114",
    "ok115",
    "ok116",
    "ok117",
    "ok118",
    "ok119",
    "ok120",
    "ok121",
    "ok122",
    "ok123",
    "ok124",
    "ok125",
    "ok126",
    "ok127",
    "ok128",
    "ok129",
    "ok130",
    "ok131",
    "ok132",
    "ok133",
    "ok134",
    "ok135",
    "ok136",
    "ok137",
    "ok138",
    "ok139",
    "ok140",
    "ok141",
    "ok142",
    "ok143",
    "ok144",
    "ok145",
    "ok146",
    "ok147",
    "ok148",
    "ok149",
    "ok150",
    "ok151",
    "ok152",
    "ok153",
    "ok154",
    "ok155",
    "ok156",
    "ok157",
    "ok158",
    "ok159",
    "ok160",
    "ok161",
    "ok162",
    "ok163",
    "ok164",
    "ok165",
    "ok166",
    "ok167",
    "ok168",
    "ok169",
    "ok170",
    "ok171",
    "ok172",
    "ok173",
    "ok174",
    "ok175",
    "ok176",
    "ok177",
    "ok178",
    "ok179",
    "ok180",
    "ok181",
    "ok182",
    "ok183",
    "ok184",
    "ok185",
    "ok186",
    "ok187",
    "ok188",
    "ok189",
    "ok190",
    "ok191",
    "ok192",
    "ok193",
    "ok194",
    "ok195",
    "ok196",
    "ok197",
    "ok198",
    "ok199",
    "ok200"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_SITE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pagezoomguard flags ZOOM_SITE_DUPLICATE', () => {
  const snapshot = {
  "sites": [
    {
      "host": "dup"
    },
    {
      "host": "dup"
    }
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.ZOOM_SITE_DUPLICATE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pagezoomguard describe renders findings in order', () => {
  const snapshot = {"zoom": 49};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('pagezoomguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
