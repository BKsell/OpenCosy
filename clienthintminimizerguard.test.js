'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./clienthintminimizerguard.js');

const evaluate = mod.evaluateClientHintMinimizerGuard;
const describe = mod.describeClientHintMinimizerGuard;

test('clienthintminimizerguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('clienthintminimizerguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('clienthintminimizerguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('clienthintminimizerguard clean snapshot produces no findings', () => {
  const clean = {
  "headers": {
    "accept-ch": "sec-ch-ua, sec-ch-ua-mobile"
  },
  "url": "https://example.com/app"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('clienthintminimizerguard flags HINT_ACCEPT_CH_MISSING', () => {
  const snapshot = {
  "headers": {
    "accept-ch": ""
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINT_ACCEPT_CH_MISSING);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clienthintminimizerguard flags HINT_HIGH_ENTROPY', () => {
  const snapshot = {
  "headers": {
    "accept-ch": "sec-ch-ua-full-version"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINT_HIGH_ENTROPY);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clienthintminimizerguard flags HINT_WILDCARD', () => {
  const snapshot = {
  "headers": {
    "accept-ch": "*"
  }
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINT_WILDCARD);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('clienthintminimizerguard flags HINT_COUNT', () => {
  const snapshot = {
  "hintCount": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINT_COUNT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('clienthintminimizerguard flags HINT_NOT_HTTPS', () => {
  const snapshot = {
  "url": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.HINT_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('clienthintminimizerguard describe renders findings in order', () => {
  const snapshot = {"headers": {"accept-ch": ""}};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('clienthintminimizerguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
