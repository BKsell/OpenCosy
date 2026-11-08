'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./downloaddangerousfileguard.js');

const evaluate = mod.evaluateDownloadDangerousFileGuard;
const describe = mod.describeDownloadDangerousFileGuard;

test('downloaddangerousfileguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('downloaddangerousfileguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('downloaddangerousfileguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('downloaddangerousfileguard clean snapshot produces no findings', () => {
  const clean = {
  "url": "https://example.com/a.exe",
  "blockedExtensions": [
    ".exe",
    ".scr"
  ],
  "filename": "report.pdf",
  "maxName": 255
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('downloaddangerousfileguard flags DOWNLOAD_DOUBLE_EXT', () => {
  const snapshot = {
  "filename": "invoice.pdf.exe"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DOWNLOAD_DOUBLE_EXT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('downloaddangerousfileguard flags DOWNLOAD_NAME_TRAVERSAL', () => {
  const snapshot = {
  "filename": ".."
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DOWNLOAD_NAME_TRAVERSAL);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('downloaddangerousfileguard flags DOWNLOAD_NAME_TOO_LONG', () => {
  const snapshot = {
  "filename": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DOWNLOAD_NAME_TOO_LONG);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('downloaddangerousfileguard flags DOWNLOAD_URL_NOT_HTTPS', () => {
  const snapshot = {
  "url": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DOWNLOAD_URL_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('downloaddangerousfileguard describe renders findings in order', () => {
  const snapshot = {"filename": "invoice.pdf.exe"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('downloaddangerousfileguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
