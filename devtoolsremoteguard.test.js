'use strict';

const test = require('node:test');
const assert = require('node:assert');
const mod = require('./devtoolsremoteguard.js');

const evaluate = mod.evaluateDevtoolsRemoteGuard;
const describe = mod.describeDevtoolsRemoteGuard;

test('devtoolsremoteguard exposes a reason table', () => {
  const keys = Object.keys(mod.REASON);
  assert.ok(keys.length >= 3);
  for (const key of keys) {
    assert.match(mod.REASON[key], /^[a-z0-9-]+$/);
  }
});

test('devtoolsremoteguard exports callable entries and limits', () => {
  assert.strictEqual(typeof evaluate, 'function');
  assert.strictEqual(typeof describe, 'function');
  assert.strictEqual(typeof mod.LIMITS, 'object');
});

test('devtoolsremoteguard accepts empty input without throwing', () => {
  const result = evaluate(undefined, undefined);
  assert.ok(Array.isArray(result.findings));
  assert.strictEqual(typeof result.blocking, 'boolean');
  assert.ok(result.options);
});

test('devtoolsremoteguard clean snapshot produces no findings', () => {
  const clean = {
  "enabled": false,
  "port": 9222,
  "bind": "127.0.0.1",
  "token": ""
};
  const result = evaluate(clean, {});
  assert.deepStrictEqual(result.findings, []);
  assert.strictEqual(result.blocking, false);
});

test('devtoolsremoteguard flags DEVTOOLS_ENABLED_RISK', () => {
  const snapshot = {
  "enabled": true
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DEVTOOLS_ENABLED_RISK);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('devtoolsremoteguard flags DEVTOOLS_PORT_RANGE', () => {
  const snapshot = {
  "port": 1023
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DEVTOOLS_PORT_RANGE);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, false);
});

test('devtoolsremoteguard flags DEVTOOLS_PUBLIC_BIND', () => {
  const snapshot = {
  "bind": "*"
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DEVTOOLS_PUBLIC_BIND);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('devtoolsremoteguard flags DEVTOOLS_TOKEN_SHORT', () => {
  const snapshot = {
  "tokenLength": -1
};
  const result = evaluate(snapshot, {});
  const finding = result.findings.find((entry) => entry.reason === mod.REASON.DEVTOOLS_TOKEN_SHORT);
  assert.ok(finding);
  assert.strictEqual(finding.blocking, true);
});

test('devtoolsremoteguard describe renders findings in order', () => {
  const snapshot = {"enabled": true};
  const result = evaluate(snapshot, {});
  const summary = describe(result);
  assert.match(summary, /: /);
  assert.strictEqual(describe({ findings: [] }), 'no findings');
  assert.strictEqual(describe(null), 'no findings');
});

test('devtoolsremoteguard tolerates primitive snapshots', () => {
  for (const probe of ['x', 0, true, [], null]) {
    const result = evaluate(probe, probe);
    assert.ok(Array.isArray(result.findings));
    assert.ok(Array.isArray(result.warnings));
  }
});
