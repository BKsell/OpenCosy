'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./crossoriginembedderpolicyguard.js');

const evaluate = mod.evaluateCrossOriginEmbedderPolicyGuard;
const describe = mod.describeCrossOriginEmbedderPolicyGuard;

test('crossoriginembedderpolicyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('crossoriginembedderpolicyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('crossoriginembedderpolicyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('crossoriginembedderpolicyguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "cross-origin-embedder-policy": "require-corp"
  }
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('crossoriginembedderpolicyguard flags COEP_MISSING', () => {
  const snapshot = {
  "headers": {
    "cross-origin-embedder-policy": ""
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COEP_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crossoriginembedderpolicyguard flags COEP_INSECURE', () => {
  const snapshot = {
  "headers": {
    "cross-origin-embedder-policy": "zzz-unknown"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COEP_INSECURE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crossoriginembedderpolicyguard flags COEP_WILDCARD', () => {
  const snapshot = {
  "headers": {
    "cross-origin-embedder-policy": "*"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COEP_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crossoriginembedderpolicyguard flags COEP_REPORT_AGE', () => {
  const snapshot = {
  "headers": {
    "cross-origin-embedder-policy-report-age": -1
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COEP_REPORT_AGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('crossoriginembedderpolicyguard describe renders findings in order', () => {
  const snapshot = {"headers": {"cross-origin-embedder-policy": ""}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('crossoriginembedderpolicyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
