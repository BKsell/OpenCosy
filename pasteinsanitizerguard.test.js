'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./pasteinsanitizerguard.js');

const evaluate = mod.evaluatePasteInSanitizerGuard;
const describe = mod.describePasteInSanitizerGuard;

test('pasteinsanitizerguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('pasteinsanitizerguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('pasteinsanitizerguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('pasteinsanitizerguard clean snapshot produces no findings', () => {
  const clean = {
  "stripHtml": true,
  "allowImages": false,
  "maxLength": 65536,
  "mimes": [
    "text/plain"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('pasteinsanitizerguard flags PASTE_STRIP_OFF', () => {
  const snapshot = {
  "stripOff": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PASTE_STRIP_OFF);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('pasteinsanitizerguard flags PASTE_IMAGE_RISK', () => {
  const snapshot = {
  "allowImages": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PASTE_IMAGE_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pasteinsanitizerguard flags PASTE_MIME_UNKNOWN', () => {
  const snapshot = {
  "mimes": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PASTE_MIME_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('pasteinsanitizerguard flags PASTE_LENGTH_RANGE', () => {
  const snapshot = {
  "maxLength": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PASTE_LENGTH_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pasteinsanitizerguard flags PASTE_MIME_EMPTY', () => {
  const snapshot = {
  "mimes": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PASTE_MIME_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('pasteinsanitizerguard describe renders findings in order', () => {
  const snapshot = {"stripOff": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('pasteinsanitizerguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
