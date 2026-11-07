'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./speculationrulesguard');

function h(value) {
  return { 'speculation-rules': [value] };
}

test('缺头返回 missing 且不改动', () => {
  const headers = {};
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('同源相对路径不改动', () => {
  const headers = h('/rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
});

test('同源绝对路径不改动', () => {
  const headers = h('"https://example.com/rules.json"');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, false);
});

test('跨源来源被剥除', () => {
  const headers = h('https://cdn.example.net/rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CROSS_ORIGIN);
  assert.strictEqual(headers['speculation-rules'], undefined);
});

test('明文来源被剥除', () => {
  const headers = h('http://example.com/rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'http://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('file 来源被剥除', () => {
  const headers = h('file:///etc/passwd');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('data 来源被剥除', () => {
  const headers = h('data:text/plain,hello');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.INSECURE);
});

test('内嵌凭据被剥除', () => {
  const headers = h('https://user:pass@example.com/rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CREDENTIALS);
});

test('路径穿越被剥除', () => {
  const headers = h('/../../etc/rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.PATH_SHAPE);
});

test('反斜杠路径被剥除', () => {
  const headers = h('\\rules.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.PATH_SHAPE);
});

test('多来源被剥除', () => {
  const headers = h('/a.json, /b.json');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MULTIPLE);
});

test('空值整头剥除', () => {
  const headers = h('   ');
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.MALFORMED);
});

test('超长取值整头剥除', () => {
  const headers = h(`/${'a'.repeat(600)}.json`);
  const r = guard.applySpeculationRulesGuard(headers, 'https://example.com');
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});

test('描述覆盖所有状态', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
