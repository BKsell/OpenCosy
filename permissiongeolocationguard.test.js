'use strict';

const assert = require('node:assert');
const { test } = require('node:test');
const guard = require('./permissiongeolocationguard.js');

const REASONS = ["PERMGEO_FLAG_OFF", "PERMGEO_REPORT_ONLY", "PERMGEO_MODE_INVALID", "PERMGEO_COUNT_OUT_OF_RANGE", "PERMGEO_ENDPOINT_INSECURE", "PERMGEO_ENDPOINT_TOO_LONG", "PERMGEO_NOTE_CONTROL", "PERMGEO_PATH_TRAVERSAL", "PERMGEO_ITEM_UNKNOWN", "PERMGEO_ITEM_DUPLICATE", "PERMGEO_ITEM_COUNT", "PERMGEO_BASELINE_EMPTY"];
const CLEAN = {
  "permGeo": {
    "enabled": true,
    "reportOnly": false,
    "mode": "deny",
    "lifetime": 480,
    "endpoint": "https://geo.example.com/policy",
    "note": "geo-note",
    "storagePath": "policies/geo",
    "items": [
      "geolocation=()"
    ],
    "baseline": [
      "geo"
    ]
  }
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function withValue(path, value) {
  const snapshot = clone(CLEAN);
  const parts = path.split('.');
  let cursor = snapshot;
  for (const part of parts.slice(0, -1)) {
    if (typeof cursor[part] !== 'object' || cursor[part] === null) {
      cursor[part] = {};
    }
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
  return snapshot;
}

function hasKey(result, key) {
  return result.findings.some((finding) => finding.key === key);
}

test('reason table covers every rule', () => {
  assert.deepStrictEqual(guard.RULES.map((rule) => rule.key), REASONS);
});

test('exported evaluator is callable', () => {
  assert.strictEqual(typeof guard.evaluatePermissiongeolocationGuard, 'function');
  assert.strictEqual(typeof guard.describePermissiongeolocationGuard, 'function');
});

test('empty input is rejected without throwing', () => {
  const result = guard.evaluatePermissiongeolocationGuard(undefined);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});

test('clean snapshot produces no findings', () => {
  const result = guard.evaluatePermissiongeolocationGuard(clone(CLEAN));
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.ok, true);
});

test('rule PERMGEO_FLAG_OFF triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.enabled', false));
  assert.ok(hasKey(result, 'PERMGEO_FLAG_OFF'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_FLAG_OFF');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMGEO_REPORT_ONLY triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.reportOnly', true));
  assert.ok(hasKey(result, 'PERMGEO_REPORT_ONLY'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_REPORT_ONLY');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_MODE_INVALID triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.mode', "bogus-value"));
  assert.ok(hasKey(result, 'PERMGEO_MODE_INVALID'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_MODE_INVALID');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMGEO_COUNT_OUT_OF_RANGE triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.lifetime', 119));
  assert.ok(hasKey(result, 'PERMGEO_COUNT_OUT_OF_RANGE'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_COUNT_OUT_OF_RANGE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_ENDPOINT_INSECURE triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.endpoint', "BAD VALUE!"));
  assert.ok(hasKey(result, 'PERMGEO_ENDPOINT_INSECURE'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_ENDPOINT_INSECURE');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMGEO_ENDPOINT_TOO_LONG triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.endpoint', "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
  assert.ok(hasKey(result, 'PERMGEO_ENDPOINT_TOO_LONG'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_ENDPOINT_TOO_LONG');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_NOTE_CONTROL triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.note', "a\u0007b"));
  assert.ok(hasKey(result, 'PERMGEO_NOTE_CONTROL'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_NOTE_CONTROL');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_PATH_TRAVERSAL triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.storagePath', "../etc/passwd"));
  assert.ok(hasKey(result, 'PERMGEO_PATH_TRAVERSAL'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_PATH_TRAVERSAL');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMGEO_ITEM_UNKNOWN triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.items', ["bogus-item"]));
  assert.ok(hasKey(result, 'PERMGEO_ITEM_UNKNOWN'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_ITEM_UNKNOWN');
  assert.strictEqual(finding.blocking, true);
});

test('rule PERMGEO_ITEM_DUPLICATE triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.items', ["dup", "dup"]));
  assert.ok(hasKey(result, 'PERMGEO_ITEM_DUPLICATE'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_ITEM_DUPLICATE');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_ITEM_COUNT triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.items', ["filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled", "filled"]));
  assert.ok(hasKey(result, 'PERMGEO_ITEM_COUNT'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_ITEM_COUNT');
  assert.strictEqual(finding.blocking, false);
});

test('rule PERMGEO_BASELINE_EMPTY triggers on a violating value', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.baseline', []));
  assert.ok(hasKey(result, 'PERMGEO_BASELINE_EMPTY'));
  const finding = result.findings.find((item) => item.key === 'PERMGEO_BASELINE_EMPTY');
  assert.strictEqual(finding.blocking, false);
});


test('describe renders the triggered finding', () => {
  const result = guard.evaluatePermissiongeolocationGuard(withValue('permGeo.enabled', false));
  const text = guard.describePermissiongeolocationGuard(result);
  assert.ok(text.includes('PERMGEO_FLAG_OFF'));
  assert.ok(text.length > 'permissiongeolocationguard:'.length);
});

test('describe tolerates a malformed result', () => {
  const text = guard.describePermissiongeolocationGuard(null);
  assert.ok(text.includes('invalid result'));
});

test('array snapshot does not throw', () => {
  const result = guard.evaluatePermissiongeolocationGuard([]);
  assert.strictEqual(result.ok, false);
  assert.ok(hasKey(result, 'SNAPSHOT_INVALID'));
});
