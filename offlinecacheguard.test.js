'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./offlinecacheguard.js');

const evaluate = mod.evaluateOfflineCacheGuard;
const describe = mod.describeOfflineCacheGuard;

test('offlinecacheguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('offlinecacheguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('offlinecacheguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('offlinecacheguard clean snapshot produces no findings', () => {
  const clean = {
  "url": "https://example.com/",
  "entries": [
    {
      "url": "https://example.com/a",
      "ttl": 60
    }
  ],
  "maxBytes": 8388608
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('offlinecacheguard flags CACHE_URL_NOT_HTTPS', () => {
  const snapshot = {
  "url": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_URL_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('offlinecacheguard flags CACHE_ENTRY_NOT_HTTPS', () => {
  const snapshot = {
  "entries": [
    "http://insecure.test/x"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_ENTRY_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('offlinecacheguard flags CACHE_TTL_RANGE', () => {
  const snapshot = {
  "entries": [
    -1
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_TTL_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('offlinecacheguard flags CACHE_ENTRY_LIMIT', () => {
  const snapshot = {
  "entries": [
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
    "ok200",
    "ok201",
    "ok202",
    "ok203",
    "ok204",
    "ok205",
    "ok206",
    "ok207",
    "ok208",
    "ok209",
    "ok210",
    "ok211",
    "ok212",
    "ok213",
    "ok214",
    "ok215",
    "ok216",
    "ok217",
    "ok218",
    "ok219",
    "ok220",
    "ok221",
    "ok222",
    "ok223",
    "ok224",
    "ok225",
    "ok226",
    "ok227",
    "ok228",
    "ok229",
    "ok230",
    "ok231",
    "ok232",
    "ok233",
    "ok234",
    "ok235",
    "ok236",
    "ok237",
    "ok238",
    "ok239",
    "ok240",
    "ok241",
    "ok242",
    "ok243",
    "ok244",
    "ok245",
    "ok246",
    "ok247",
    "ok248",
    "ok249",
    "ok250",
    "ok251",
    "ok252",
    "ok253",
    "ok254",
    "ok255",
    "ok256",
    "ok257",
    "ok258",
    "ok259",
    "ok260",
    "ok261",
    "ok262",
    "ok263",
    "ok264",
    "ok265",
    "ok266",
    "ok267",
    "ok268",
    "ok269",
    "ok270",
    "ok271",
    "ok272",
    "ok273",
    "ok274",
    "ok275",
    "ok276",
    "ok277",
    "ok278",
    "ok279",
    "ok280",
    "ok281",
    "ok282",
    "ok283",
    "ok284",
    "ok285",
    "ok286",
    "ok287",
    "ok288",
    "ok289",
    "ok290",
    "ok291",
    "ok292",
    "ok293",
    "ok294",
    "ok295",
    "ok296",
    "ok297",
    "ok298",
    "ok299",
    "ok300",
    "ok301",
    "ok302",
    "ok303",
    "ok304",
    "ok305",
    "ok306",
    "ok307",
    "ok308",
    "ok309",
    "ok310",
    "ok311",
    "ok312",
    "ok313",
    "ok314",
    "ok315",
    "ok316",
    "ok317",
    "ok318",
    "ok319",
    "ok320",
    "ok321",
    "ok322",
    "ok323",
    "ok324",
    "ok325",
    "ok326",
    "ok327",
    "ok328",
    "ok329",
    "ok330",
    "ok331",
    "ok332",
    "ok333",
    "ok334",
    "ok335",
    "ok336",
    "ok337",
    "ok338",
    "ok339",
    "ok340",
    "ok341",
    "ok342",
    "ok343",
    "ok344",
    "ok345",
    "ok346",
    "ok347",
    "ok348",
    "ok349",
    "ok350",
    "ok351",
    "ok352",
    "ok353",
    "ok354",
    "ok355",
    "ok356",
    "ok357",
    "ok358",
    "ok359",
    "ok360",
    "ok361",
    "ok362",
    "ok363",
    "ok364",
    "ok365",
    "ok366",
    "ok367",
    "ok368",
    "ok369",
    "ok370",
    "ok371",
    "ok372",
    "ok373",
    "ok374",
    "ok375",
    "ok376",
    "ok377",
    "ok378",
    "ok379",
    "ok380",
    "ok381",
    "ok382",
    "ok383",
    "ok384",
    "ok385",
    "ok386",
    "ok387",
    "ok388",
    "ok389",
    "ok390",
    "ok391",
    "ok392",
    "ok393",
    "ok394",
    "ok395",
    "ok396",
    "ok397",
    "ok398",
    "ok399",
    "ok400",
    "ok401",
    "ok402",
    "ok403",
    "ok404",
    "ok405",
    "ok406",
    "ok407",
    "ok408",
    "ok409",
    "ok410",
    "ok411",
    "ok412",
    "ok413",
    "ok414",
    "ok415",
    "ok416",
    "ok417",
    "ok418",
    "ok419",
    "ok420",
    "ok421",
    "ok422",
    "ok423",
    "ok424",
    "ok425",
    "ok426",
    "ok427",
    "ok428",
    "ok429",
    "ok430",
    "ok431",
    "ok432",
    "ok433",
    "ok434",
    "ok435",
    "ok436",
    "ok437",
    "ok438",
    "ok439",
    "ok440",
    "ok441",
    "ok442",
    "ok443",
    "ok444",
    "ok445",
    "ok446",
    "ok447",
    "ok448",
    "ok449",
    "ok450",
    "ok451",
    "ok452",
    "ok453",
    "ok454",
    "ok455",
    "ok456",
    "ok457",
    "ok458",
    "ok459",
    "ok460",
    "ok461",
    "ok462",
    "ok463",
    "ok464",
    "ok465",
    "ok466",
    "ok467",
    "ok468",
    "ok469",
    "ok470",
    "ok471",
    "ok472",
    "ok473",
    "ok474",
    "ok475",
    "ok476",
    "ok477",
    "ok478",
    "ok479",
    "ok480",
    "ok481",
    "ok482",
    "ok483",
    "ok484",
    "ok485",
    "ok486",
    "ok487",
    "ok488",
    "ok489",
    "ok490",
    "ok491",
    "ok492",
    "ok493",
    "ok494",
    "ok495",
    "ok496",
    "ok497",
    "ok498",
    "ok499",
    "ok500"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_ENTRY_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('offlinecacheguard flags CACHE_SIZE_LIMIT', () => {
  const snapshot = {
  "maxBytes": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_SIZE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('offlinecacheguard flags CACHE_ENTRY_EMPTY_URL', () => {
  const snapshot = {
  "entries": [
    ""
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CACHE_ENTRY_EMPTY_URL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('offlinecacheguard describe renders findings in order', () => {
  const snapshot = {"url": "http://insecure.test/x"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('offlinecacheguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
