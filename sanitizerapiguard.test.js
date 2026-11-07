'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./sanitizerapiguard.js');

const evaluate = mod.evaluateSanitizerApiGuard;
const describe = mod.describeSanitizerApiGuard;

test('sanitizerapiguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('sanitizerapiguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('sanitizerapiguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('sanitizerapiguard clean snapshot produces no findings', () => {
  const clean = {
  "namespace": "default",
  "elements": [
    "p",
    "span"
  ],
  "attributes": [
    "class"
  ]
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('sanitizerapiguard flags SANITIZER_NAMESPACE', () => {
  const snapshot = {
  "namespace": "zzz-unknown"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_NAMESPACE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('sanitizerapiguard flags SANITIZER_ELEMENT_WILDCARD', () => {
  const snapshot = {
  "elements": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_ELEMENT_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('sanitizerapiguard flags SANITIZER_SCRIPT_ELEMENT', () => {
  const snapshot = {
  "elements": [
    "script"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_SCRIPT_ELEMENT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('sanitizerapiguard flags SANITIZER_ATTRIBUTE_WILDCARD', () => {
  const snapshot = {
  "attributes": [
    "*"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_ATTRIBUTE_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sanitizerapiguard flags SANITIZER_ELEMENT_LIMIT', () => {
  const snapshot = {
  "elements": [
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
    "ok40"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_ELEMENT_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sanitizerapiguard flags SANITIZER_ATTRIBUTE_LIMIT', () => {
  const snapshot = {
  "attributes": [
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
    "ok20"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.SANITIZER_ATTRIBUTE_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('sanitizerapiguard describe renders findings in order', () => {
  const snapshot = {"namespace": "zzz-unknown"};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('sanitizerapiguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
