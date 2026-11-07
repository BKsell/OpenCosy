'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./earlyhintsguard.js');

const evaluate = mod.evaluateEarlyHintsGuard;
const describe = mod.describeEarlyHintsGuard;

test('earlyhintsguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('earlyhintsguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('earlyhintsguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('earlyhintsguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "link": "<https://cdn.example.com/app.css>; rel=preload; as=style"
  }
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('earlyhintsguard flags HINTS_MISSING', () => {
  const snapshot = {
  "headers": {
    "link": ""
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINTS_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('earlyhintsguard flags HINTS_NOT_HTTPS', () => {
  const snapshot = {
  "headers": {
    "link": "<http://cdn.example.com/x>"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINTS_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('earlyhintsguard flags HINTS_WILDCARD', () => {
  const snapshot = {
  "headers": {
    "link": "<https://*/x>"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINTS_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('earlyhintsguard flags HINTS_COUNT', () => {
  const snapshot = {
  "hintCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINTS_COUNT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('earlyhintsguard describe renders findings in order', () => {
  const snapshot = {"headers": {"link": ""}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('earlyhintsguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
