'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./clipboardpasteconfirmguard.js');

const evaluate = mod.evaluateClipboardPasteConfirmGuard;
const describe = mod.describeClipboardPasteConfirmGuard;

test('clipboardpasteconfirmguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('clipboardpasteconfirmguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('clipboardpasteconfirmguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('clipboardpasteconfirmguard clean snapshot produces no findings', () => {
  const clean = {
  "confirmBeforePaste": true,
  "mimes": [
    "text/plain"
  ],
  "maxBytes": 1048576
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('clipboardpasteconfirmguard flags CLIPBOARD_CONFIRM_OFF', () => {
  const snapshot = {
  "confirmBeforePaste": false
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLIPBOARD_CONFIRM_OFF);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clipboardpasteconfirmguard flags CLIPBOARD_MIME_UNKNOWN', () => {
  const snapshot = {
  "mimes": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLIPBOARD_MIME_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('clipboardpasteconfirmguard flags CLIPBOARD_SIZE_RANGE', () => {
  const snapshot = {
  "maxBytes": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLIPBOARD_SIZE_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clipboardpasteconfirmguard flags CLIPBOARD_MIME_EMPTY', () => {
  const snapshot = {
  "mimes": []
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.CLIPBOARD_MIME_EMPTY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clipboardpasteconfirmguard describe renders findings in order', () => {
  const snapshot = {"confirmBeforePaste": false};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('clipboardpasteconfirmguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
