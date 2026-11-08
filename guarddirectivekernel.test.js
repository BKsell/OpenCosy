'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeDirectiveGuard, LIMITS } = require('./guarddirectivekernel');

const guard = makeDirectiveGuard({ prefix: 'UNIT', label: 'Unit directive' });

function clean() {
  return {
    policy: {
      enabled: true,
      reportOnly: false,
      mode: 'enforce',
      maxItems: 8,
      endpoint: 'https://ok.example.com/report',
      note: 'plain note',
      fallbackPath: 'logs/run.log',
      items: ['default-src', 'img-src'],
      baseline: ['self'],
    },
  };
}

test('rules carry the prefix and keep twelve entries', () => {
  assert.equal(guard.RULES.length, 12);
  for (const rule of guard.RULES) {
    assert.equal(rule.key.startsWith('UNIT_'), true);
    assert.equal(rule.message.startsWith('Unit directive'), true);
    assert.equal(rule.path.startsWith('policy.'), true);
  }
});

test('limits stay at 32 items and 512 characters', () => {
  assert.deepEqual(guard.LIMITS, { maxItems: 32, maxLength: 512 });
  assert.deepEqual(LIMITS, guard.LIMITS);
});

test('clean policy is valid and not blocking', () => {
  const result = guard.evaluate(clean());
  assert.equal(result.valid, true);
  assert.equal(result.blocking, false);
  assert.deepEqual(result.findings, []);
  assert.deepEqual(result.reasonCodes, []);
});

test('flat config misses every nested field', () => {
  const result = guard.evaluate({ enabled: true, mode: 'enforce' });
  assert.equal(result.valid, false);
  assert.equal(result.blocking, true);
  assert.equal(result.findings.length, 12);
  for (const finding of result.findings) {
    assert.equal(finding.detail, 'missing value');
  }
});

test('boolean strings are tolerated', () => {
  const config = clean();
  config.policy.enabled = 'TRUE';
  config.policy.reportOnly = ' false ';
  assert.equal(guard.evaluate(config).valid, true);
});

test('non object config adds a blocking config error', () => {
  const result = guard.evaluate('policy');
  assert.equal(result.findings[0].key, 'UNIT_CONFIG_INVALID');
  assert.equal(result.findings[0].detail, 'got string');
  assert.equal(result.blocking, true);
});

test('endpoint must be https', () => {
  const config = clean();
  config.policy.endpoint = 'http://plain.example.com/report';
  const result = guard.evaluate(config);
  assert.deepEqual(result.reasonCodes, ['UNIT_ENDPOINT_INSECURE']);
  assert.equal(result.blocking, true);
});

test('fallback path rejects any parent segment', () => {
  const config = clean();
  config.policy.fallbackPath = 'logs/../escape';
  const result = guard.evaluate(config);
  assert.deepEqual(result.reasonCodes, ['UNIT_PATH_TRAVERSAL']);
  assert.equal(result.findings[0].detail, 'path segment ".." is not allowed');
  config.policy.fallbackPath = 'C:\\logs\\run.log';
  assert.equal(guard.evaluate(config).valid, true);
});

test('duplicate detection folds case and whitespace', () => {
  const config = clean();
  config.policy.items = ['default-src', 'DEFAULT-SRC '];
  const result = guard.evaluate(config);
  assert.deepEqual(result.reasonCodes, ['UNIT_ITEM_DUPLICATE']);
  assert.equal(result.findings[0].detail, 'duplicate entry default-src');
});

test('unknown directive is reported in lowercase', () => {
  const config = clean();
  config.policy.items = ['SELF-PROMO'];
  const result = guard.evaluate(config);
  assert.deepEqual(result.reasonCodes, ['UNIT_ITEM_UNKNOWN']);
  assert.equal(result.findings[0].detail, 'entry self-promo is not in the allowlist');
});

test('item budget stops at sixteen entries', () => {
  const config = clean();
  config.policy.items = new Array(17).fill('img-src');
  const result = guard.evaluate(config);
  assert.deepEqual(result.reasonCodes, ['UNIT_ITEM_DUPLICATE', 'UNIT_ITEM_COUNT']);
  assert.equal(result.findings[1].detail, 'count 17 exceeds 16');
});

test('describe joins findings and reports the clean case', () => {
  assert.equal(guard.describe(clean()), 'Unit directive 配置满足基线要求');
  const config = clean();
  config.policy.enabled = false;
  const text = guard.describe(config);
  assert.equal(text, 'UNIT_FLAG_OFF:expected true, got boolean');
});
