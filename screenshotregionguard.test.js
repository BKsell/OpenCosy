'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./screenshotregionguard.js');

const evaluate = mod.evaluateScreenshotRegionGuard;
const describe = mod.describeScreenshotRegionGuard;

test('screenshotregionguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('screenshotregionguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('screenshotregionguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('screenshotregionguard clean snapshot produces no findings', () => {
  const clean = {
  "savePath": "shots",
  "format": "png",
  "quality": 90,
  "includeCursor": false
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('screenshotregionguard flags SHOT_PATH_TRAVERSAL', () => {
  const snapshot = {
  "savePath": ".."
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHOT_PATH_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('screenshotregionguard flags SHOT_FORMAT_UNKNOWN', () => {
  const snapshot = {
  "format": "zzz-unknown"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHOT_FORMAT_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('screenshotregionguard flags SHOT_QUALITY_RANGE', () => {
  const snapshot = {
  "quality": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHOT_QUALITY_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('screenshotregionguard flags SHOT_CURSOR_RISK', () => {
  const snapshot = {
  "includeCursor": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHOT_CURSOR_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('screenshotregionguard flags SHOT_WIDTH_RANGE', () => {
  const snapshot = {
  "width": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SHOT_WIDTH_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('screenshotregionguard describe renders findings in order', () => {
  const snapshot = {"savePath": ".."};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('screenshotregionguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
