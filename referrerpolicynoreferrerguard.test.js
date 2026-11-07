'use strict';

const assert = require('node:assert');
const { test } = require('node:test');

const {
  RULES,
  LIMITS,
  evaluateReferrerpolicynoreferrerGuard,
  describeReferrerpolicynoreferrerGuard,
} = require('./referrerpolicynoreferrerguard.js');

const CLEAN = {
  policy: {
    enabled: true,
    reportOnly: false,
    mode: 'enforce',
    maxItems: 8,
    endpoint: 'https://example.com/report',
    note: 'ok',
    fallbackPath: 'fallback.html',
    items: ['default-src', 'script-src'],
    baseline: ['default-src'],
  },
};

function isPlain(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function withValue(path, value) {
  const clone = JSON.parse(JSON.stringify(CLEAN));
  const parts = path.split('.');
  let node = clone;
  for (let index = 0; index < parts.length - 1; index += 1) {
    if (!isPlain(node[parts[index]])) {
      node[parts[index]] = {};
    }
    node = node[parts[index]];
  }
  node[parts[parts.length - 1]] = value;
  return clone;
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

test('clean configuration produces no findings', () => {
  const result = evaluateReferrerpolicynoreferrerGuard(CLEAN);
  assert.strictEqual(result.valid, true);
  assert.strictEqual(result.blocking, false);
  assert.deepStrictEqual(result.reasonCodes, []);
});

test('describe renders the baseline message for a clean configuration', () => {
  const text = describeReferrerpolicynoreferrerGuard(CLEAN);
  assert.ok(typeof text === 'string' && text.length > 0);
});

test('describe lists reason codes for a violating configuration', () => {
  const config = withValue('policy.enabled', false);
  const result = evaluateReferrerpolicynoreferrerGuard(config);
  const text = describeReferrerpolicynoreferrerGuard(config);
  assert.ok(text.includes(result.reasonCodes[0]));
  assert.ok(text.includes(':'));
});

test('rule table exposes twelve entries', () => {
  assert.strictEqual(RULES.length, 12);
  for (const rule of RULES) {
    assert.ok(typeof rule.key === 'string' && rule.key.length > 0);
    assert.ok(typeof rule.kind === 'string');
    assert.ok(typeof rule.path === 'string');
  }
});

test('limits expose the documented budgets', () => {
  assert.strictEqual(LIMITS.maxItems, 32);
  assert.strictEqual(LIMITS.maxLength, 512);
});

test('null configuration trips every rule', () => {
  const result = evaluateReferrerpolicynoreferrerGuard(null);
  assert.strictEqual(result.findings.length, RULES.length);
  assert.strictEqual(result.blocking, true);
});

test('undefined configuration trips every rule', () => {
  const result = evaluateReferrerpolicynoreferrerGuard(undefined);
  assert.strictEqual(result.findings.length, RULES.length);
});

test('primitive configuration is reported as invalid input', () => {
  const result = evaluateReferrerpolicynoreferrerGuard('not-an-object');
  assert.strictEqual(result.blocking, true);
  assert.ok(result.reasonCodes.includes('REFERRERP_CONFIG_INVALID'));
});

test('blocking flag is aggregated from the findings', () => {
  const config = withValue('policy.endpoint', 'http://example.com/report');
  const result = evaluateReferrerpolicynoreferrerGuard(config);
  assert.strictEqual(result.blocking, true);
});

test('non blocking findings keep the guard non blocking', () => {
  const config = withValue('policy.reportOnly', true);
  const result = evaluateReferrerpolicynoreferrerGuard(config);
  assert.strictEqual(result.blocking, false);
  assert.ok(result.reasonCodes.includes('REFERRERP_REPORT_ONLY'));
});

test('withValue rebuilds missing parent objects', () => {
  const config = withValue('policy.items', ['default-src']);
  const result = evaluateReferrerpolicynoreferrerGuard(config);
  assert.strictEqual(result.valid, true);
});

for (const rule of RULES) {
  test('rule ' + rule.key + ' reports its reason code on invalid input', () => {
    const config = withValue(rule.path, badValueFor(rule));
    const result = evaluateReferrerpolicynoreferrerGuard(config);
    assert.ok(
      result.reasonCodes.includes(rule.key),
      'expected ' + rule.key + ' in ' + JSON.stringify(result.reasonCodes),
    );
    assert.strictEqual(result.findings.length >= 1, true);
  });
}
