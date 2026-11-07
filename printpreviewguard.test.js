'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./printpreviewguard.js');

const evaluate = mod.evaluatePrintPreviewGuard;
const describe = mod.describePrintPreviewGuard;

test('printpreviewguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('printpreviewguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('printpreviewguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('printpreviewguard clean snapshot produces no findings', () => {
  const clean = {
  "header": "confidential",
  "footer": "",
  "savePath": "out",
  "includeUrl": false,
  "maxCopies": 3
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('printpreviewguard flags PRINT_PATH_TRAVERSAL', () => {
  const snapshot = {
  "savePath": ".."
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRINT_PATH_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('printpreviewguard flags PRINT_HEADER_LONG', () => {
  const snapshot = {
  "header": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRINT_HEADER_LONG);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('printpreviewguard flags PRINT_FOOTER_LONG', () => {
  const snapshot = {
  "footer": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRINT_FOOTER_LONG);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('printpreviewguard flags PRINT_URL_REVEAL', () => {
  const snapshot = {
  "includeUrl": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRINT_URL_REVEAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('printpreviewguard flags PRINT_COPIES_RANGE', () => {
  const snapshot = {
  "maxCopies": 0
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PRINT_COPIES_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('printpreviewguard describe renders findings in order', () => {
  const snapshot = {"savePath": ".."};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('printpreviewguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
