'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeZhGuard, LIMITS } = require('./guardzhkernel');

const guard = makeZhGuard({ prefix: 'UNIT', label: '单元' });

function clean() {
  return {
    enabled: true,
    reportOnly: false,
    mode: 'enforce',
    maxItems: 8,
    endpoint: 'https://ok.example.com/report',
    note: 'plain note',
    fallbackPath: 'logs/run.log',
    items: ['default-src', 'img-src'],
    baseline: ['self'],
    origins: ['self'],
  };
}

test('rules carry the module prefix and keep thirteen entries', () => {
  assert.equal(guard.RULES.length, 13);
  for (const rule of guard.RULES) {
    assert.equal(rule.key.startsWith('UNIT_'), true);
    assert.equal(rule.key, 'UNIT_' + rule.key.slice('UNIT_'.length));
  }
});

test('limits stay at 32 items and 512 characters', () => {
  assert.deepEqual(guard.LIMITS, { maxItems: 32, maxLength: 512 });
  assert.deepEqual(LIMITS, guard.LIMITS);
});

test('clean policy reports no finding', () => {
  const result = guard.evaluate(clean());
  assert.equal(result.ok, true);
  assert.equal(result.blocking, false);
  assert.deepEqual(result.findings, []);
});

test('non object policy reports a blocking config error', () => {
  const result = guard.evaluate([]);
  assert.equal(result.ok, false);
  assert.equal(result.blocking, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].key, 'UNIT_CONFIG_INVALID');
});

test('disabled flag blocks and report only stays advisory', () => {
  const config = clean();
  config.enabled = false;
  config.reportOnly = true;
  const result = guard.evaluate(config);
  const keys = result.findings.map((finding) => finding.key).sort();
  assert.deepEqual(keys, ['UNIT_FLAG_OFF', 'UNIT_REPORT_ONLY']);
  assert.equal(result.blocking, true);
  assert.equal(result.findings.find((finding) => finding.key === 'UNIT_REPORT_ONLY').blocking, false);
});

test('endpoint rejects plain http and accepts https', () => {
  const config = clean();
  config.endpoint = 'http://plain.example.com/report';
  const bad = guard.evaluate(config);
  assert.equal(bad.findings[0].key, 'UNIT_ENDPOINT_INSECURE');
  config.endpoint = 'https://plain.example.com/report';
  assert.equal(guard.evaluate(config).ok, true);
});

test('endpoint length budget sits at one hundred characters', () => {
  const config = clean();
  config.endpoint = 'https://ok.example.com/' + 'a'.repeat(70);
  assert.equal(guard.evaluate(config).ok, true);
  config.endpoint = 'https://ok.example.com/' + 'a'.repeat(90);
  const result = guard.evaluate(config);
  assert.deepEqual(result.findings.map((finding) => finding.key), ['UNIT_ENDPOINT_TOO_LONG']);
  assert.equal(result.blocking, false);
});

test('fallback path blocks parent and absolute segments', () => {
  const config = clean();
  config.fallbackPath = '../escape';
  const parent = guard.evaluate(config);
  assert.equal(parent.findings[0].key, 'UNIT_PATH_TRAVERSAL');
  assert.equal(parent.blocking, true);
  config.fallbackPath = '/etc/passwd';
  assert.equal(guard.evaluate(config).findings[0].key, 'UNIT_PATH_TRAVERSAL');
});

test('item count budget sits at twelve entries', () => {
  const config = clean();
  config.items = [];
  for (let i = 0; i < 13; i += 1) {
    config.items.push(i === 0 ? 'default-src' : 'default-src');
  }
  const result = guard.evaluate(config);
  const keys = result.findings.map((finding) => finding.key);
  assert.equal(keys.includes('UNIT_ITEM_COUNT'), true);
  assert.equal(keys.includes('UNIT_ITEM_DUPLICATE'), true);
  assert.equal(result.blocking, false);
});

test('summarize splits blocking and advisory findings', () => {
  const config = clean();
  config.enabled = false;
  config.note = 'bad\u0001note';
  const summary = guard.summarize(config);
  assert.equal(summary.ok, false);
  assert.equal(summary.total, 2);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.advisory, 1);
  assert.deepEqual(summary.keys, ['UNIT_FLAG_OFF', 'UNIT_NOTE_CONTROL']);
});

test('describe caps the report at ten entries', () => {
  const config = {};
  const result = guard.evaluate(config);
  const text = guard.describe(config);
  assert.equal(result.findings.length, 13);
  assert.equal(text.startsWith('单元：'), true);
  assert.equal(text.includes('…共 13 项'), true);
  assert.equal(text.split('；').length, 11);
});

test('describe reports the clean policy with its own label', () => {
  assert.equal(guard.describe(clean()), '单元：策略配置未发现风险');
});
