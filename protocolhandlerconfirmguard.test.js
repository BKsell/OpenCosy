'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./protocolhandlerconfirmguard.js');

const evaluate = mod.evaluateProtocolHandlerConfirmGuard;
const describe = mod.describeProtocolHandlerConfirmGuard;

test('protocolhandlerconfirmguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('protocolhandlerconfirmguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('protocolhandlerconfirmguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('protocolhandlerconfirmguard clean snapshot produces no findings', () => {
  const clean = {
  "schemes": [
    "webcal"
  ],
  "autoAllow": false,
  "handlerUrl": "https://example.com/handler"
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('protocolhandlerconfirmguard flags PROTOCOL_SCHEME_UNKNOWN', () => {
  const snapshot = {
  "schemes": [
    "zzz-unknown"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROTOCOL_SCHEME_UNKNOWN);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('protocolhandlerconfirmguard flags PROTOCOL_AUTO_ALLOW_RISK', () => {
  const snapshot = {
  "autoAllow": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROTOCOL_AUTO_ALLOW_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('protocolhandlerconfirmguard flags PROTOCOL_HANDLER_NOT_HTTPS', () => {
  const snapshot = {
  "handlerUrl": "http://insecure.test/x"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROTOCOL_HANDLER_NOT_HTTPS);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('protocolhandlerconfirmguard flags PROTOCOL_SCHEME_LIMIT', () => {
  const snapshot = {
  "schemes": [
    "ok0",
    "ok1",
    "ok2",
    "ok3",
    "ok4",
    "ok5"
  ]
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.PROTOCOL_SCHEME_LIMIT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('protocolhandlerconfirmguard describe renders findings in order', () => {
  const snapshot = {"schemes": ["zzz-unknown"]};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('protocolhandlerconfirmguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
