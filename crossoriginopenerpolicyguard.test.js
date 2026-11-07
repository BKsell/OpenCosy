'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./crossoriginopenerpolicyguard.js');

const evaluate = mod.evaluateCrossOriginOpenerPolicyGuard;
const describe = mod.describeCrossOriginOpenerPolicyGuard;

test('crossoriginopenerpolicyguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('crossoriginopenerpolicyguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('crossoriginopenerpolicyguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('crossoriginopenerpolicyguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "cross-origin-opener-policy": "same-origin"
  }
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('crossoriginopenerpolicyguard flags COOP_MISSING', () => {
  const snapshot = {
  "headers": {
    "cross-origin-opener-policy": ""
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COOP_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crossoriginopenerpolicyguard flags COOP_UNSAFE', () => {
  const snapshot = {
  "headers": {
    "cross-origin-opener-policy": "zzz-unknown"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COOP_UNSAFE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('crossoriginopenerpolicyguard flags COOP_ALLOW_POPUPS', () => {
  const snapshot = {
  "headers": {
    "cross-origin-opener-policy": "same-origin-allow-popups"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COOP_ALLOW_POPUPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('crossoriginopenerpolicyguard flags COOP_POPUPS_LIMIT', () => {
  const snapshot = {
  "headers": {
    "cross-origin-opener-policy-popup-count": -1
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.COOP_POPUPS_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('crossoriginopenerpolicyguard describe renders findings in order', () => {
  const snapshot = {"headers": {"cross-origin-opener-policy": ""}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('crossoriginopenerpolicyguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
