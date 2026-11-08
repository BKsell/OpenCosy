'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { LIMITS, makeGuard } = require('./guardkernel.js');

const guard = makeGuard({ base: 'demo', prefix: 'DEMO' });

const CLEAN = { enabled: true, reportOnly: false, mode: 'enforce', maxItems: 8, endpoint: 'https://example.com/report', note: 'ok', fallbackPath: 'fallback.html', items: ['default-src', 'script-src'], baseline: ['default-src'], origins: ['self'] };

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function badValueFor(kind) {
  switch (kind) {
    case 'boolean-true':
      return false;
    case 'boolean-false':
      return true;
    case 'value-range':
      return 0;
    case 'text-enum':
      return 'bogus-mode';
    case 'text-pattern':
      return 'http://example.com/report';
    case 'text-too-long':
      return 'x'.repeat(600);
    case 'text-control':
      return 'a\u0007b';
    case 'text-traversal':
      return '../etc/passwd';
    case 'list-empty':
      return [];
    case 'list-count':
      return new Array(40).fill('script-src');
    case 'list-duplicate':
      return ['script-src', 'script-src'];
    case 'list-item-equals':
      return ['bogus-item'];
    default:
      return undefined;
  }
}

test('clean config passes every rule', () => {
  const result = guard.evaluate(clone(CLEAN));
  assert.equal(result.ok, true);
  assert.equal(result.findings.length, 0);
});

test('non object config is rejected', () => {
  for (const value of [null, [], 'text', 7]) {
    const result = guard.evaluate(value);
    assert.equal(result.ok, false);
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0].key, 'DEMO_CONFIG_INVALID');
    assert.equal(result.findings[0].blocking, true);
  }
});

test('rules carry the module prefix and stay ordered', () => {
  assert.equal(guard.RULES.length, 13);
  for (const rule of guard.RULES) {
    assert.equal(rule.key.startsWith('DEMO_'), true);
    assert.equal(typeof rule.message, 'string');
    assert.equal(typeof rule.blocking, 'boolean');
    assert.equal(typeof rule.kind, 'string');
    assert.equal(typeof rule.path, 'string');
  }
});

test('each rule fires on its own bad value', () => {
  for (const rule of guard.RULES) {
    const config = clone(CLEAN);
    config[rule.path] = badValueFor(rule.kind);
    const result = guard.evaluate(config);
    const keys = result.findings.map((finding) => finding.key);
    assert.equal(keys.includes(rule.key), true, rule.key + ' should fire');
    assert.equal(result.ok, false);
    const finding = result.findings.find((item) => item.key === rule.key);
    assert.equal(finding.blocking, rule.blocking);
    assert.equal(typeof finding.reason, 'string');
  }
});

test('summary counts blocking and advisory', () => {
  const config = clone(CLEAN);
  config.enabled = false;
  config.reportOnly = true;
  const summary = guard.summarize(config);
  assert.equal(summary.ok, false);
  assert.equal(summary.total, 2);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.advisory, 1);
  assert.deepEqual(summary.keys, ['DEMO_FLAG_OFF', 'DEMO_REPORT_ONLY']);
});

test('describe renders every finding', () => {
  const config = clone(CLEAN);
  config.mode = 'bogus-mode';
  const text = guard.describe(config);
  assert.equal(text, 'DEMO_MODE_INVALID: mode is outside the supported set');
});

test('describe reports a clean config', () => {
  assert.equal(guard.describe(clone(CLEAN)), 'demo 配置通过全部检查');
});

test('describe truncates beyond ten findings', () => {
  const config = {
    enabled: false,
    reportOnly: true,
    mode: 'bogus-mode',
    maxItems: 0,
    endpoint: 'http://' + 'a'.repeat(600),
    note: 'a\u0007b',
    fallbackPath: '../etc/passwd',
    items: new Array(40).fill('script-src'),
    baseline: [],
    origins: ['bogus-item'],
  };
  const summary = guard.summarize(config);
  assert.equal(summary.total > 10, true);
  const text = guard.describe(config);
  assert.equal(text.split('; ').length, 11);
  assert.equal(text.endsWith('…等 ' + summary.total + ' 项'), true);
});

test('evaluation is idempotent and does not mutate input', () => {
  const config = clone(CLEAN);
  const first = guard.evaluate(config);
  const second = guard.evaluate(config);
  assert.deepEqual(first, second);
  assert.deepEqual(config, CLEAN);
});

test('limits stay inside the documented range', () => {
  assert.equal(LIMITS.maxItems, 32);
  assert.equal(LIMITS.maxLength, 512);
  assert.equal(guard.LIMITS, LIMITS);
});
