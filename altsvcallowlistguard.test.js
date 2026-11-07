'use strict';

const test = require('node:test');
const assert = require('node:assert');

const guard = require('./altsvcallowlistguard.js');

const CLEAN = {
  enabled: true,
  reportOnly: false,
  mode: 'enforce',
  maxItems: 8,
  endpoint: 'https://example.com/report',
  note: 'ok',
  fallbackPath: 'fallback.html',
  items: ['default-src', 'script-src'],
  baseline: ['default-src'],
  origins: ['self']
};

function clone(value) {
  if (Array.isArray(value)) {
    return value.map((item) => clone(item));
  }
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      out[key] = clone(value[key]);
    }
    return out;
  }
  return value;
}

function withValue(config, path, value) {
  const parts = path.split('.');
  let cursor = config;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    if (cursor[key] === undefined || cursor[key] === null) {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }
  cursor[parts[parts.length - 1]] = value;
}

function badValueFor(rule) {
  switch (rule.kind) {
    case 'value-boolean-true':
      return false;
    case 'value-boolean-false':
      return true;
    case 'value-range':
      return rule.extra[0] - 1;
    case 'text-enum':
      return 'bogus-mode';
    case 'text-pattern':
      return 'http://example.com/report';
    case 'text-too-long':
      return 'x'.repeat(rule.extra + 1);
    case 'text-control':
      return 'a\u0007b';
    case 'text-traversal':
      return '../etc/passwd';
    case 'list-empty':
      return [];
    case 'list-count':
      return new Array(rule.extra + 1).fill('default-src');
    case 'list-duplicate':
      return ['default-src', 'default-src'];
    case 'list-item-equals':
      return ['bogus-item'];
    default:
      return null;
  }
}

test('clean config passes', () => {
  const result = guard.evaluateAltsvcallowlist(clone(CLEAN));
  assert.equal(result.ok, true);
  assert.equal(result.blocking, false);
  assert.equal(result.findings.length, 0);
});

test('describe renders clean state', () => {
  const text = guard.describeAltsvcallowlist(clone(CLEAN));
  assert.equal(typeof text, 'string');
  assert.ok(text.length > 0);
  assert.ok(text.indexOf('风险') !== -1);
});

test('rules table is complete', () => {
  assert.ok(Array.isArray(guard.RULES));
  assert.ok(guard.RULES.length >= 13);
  for (const rule of guard.RULES) {
    assert.equal(typeof rule.key, 'string');
    assert.equal(typeof rule.path, 'string');
    assert.equal(typeof rule.kind, 'string');
    assert.equal(typeof rule.blocking, 'boolean');
  }
});

test('non object policy is rejected', () => {
  const result = guard.evaluateAltsvcallowlist(null);
  assert.equal(result.ok, false);
  assert.equal(result.blocking, true);
  assert.equal(result.findings.length, 1);
});

test('array policy is rejected', () => {
  const result = guard.evaluateAltsvcallowlist([]);
  assert.equal(result.ok, false);
  assert.equal(result.blocking, true);
});

test('summary counts blocking and advisory', () => {
  const config = clone(CLEAN);
  withValue(config, 'enabled', false);
  withValue(config, 'note', 'a\u0007b');
  const summary = guard.summarizeAltsvcallowlist(config);
  assert.equal(summary.ok, false);
  assert.equal(summary.total, 2);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.advisory, 1);
  assert.deepEqual(summary.keys, ['ALTSVCALL_FLAG_OFF', 'ALTSVCALL_NOTE_CONTROL']);
});

test('describe renders violations', () => {
  const config = clone(CLEAN);
  withValue(config, 'endpoint', 'http://example.com/report');
  const text = guard.describeAltsvcallowlist(config);
  assert.ok(text.indexOf('ALTSVCALL_ENDPOINT_INSECURE') !== -1);
});

test('missing fields fail closed', () => {
  const result = guard.evaluateAltsvcallowlist({});
  assert.equal(result.ok, false);
  assert.equal(result.findings.length, guard.RULES.length);
});

for (const rule of guard.RULES) {
  test('rule ' + rule.key + ' rejects bad value', () => {
    const config = clone(CLEAN);
    const bad = badValueFor(rule);
    withValue(config, rule.path, bad);
    const result = guard.evaluateAltsvcallowlist(config);
    assert.equal(result.ok, false);
    const keys = result.findings.map((item) => item.key);
    assert.ok(keys.indexOf(rule.key) !== -1);
    const hit = result.findings.filter((item) => item.key === rule.key)[0];
    assert.equal(hit.blocking, rule.blocking);
  });
}
