'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./acceptlanguageguard');

function h(value) {
  return { 'accept-language': [value] };
}

test('缺头不改动', () => {
  const r = guard.applyAcceptLanguageGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('合规标签不改动', () => {
  const headers = h('en-US, zh-CN;q=0.8');
  const r = guard.applyAcceptLanguageGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('非法标签被剔除', () => {
  const headers = h('en_US, zh-CN');
  const r = guard.applyAcceptLanguageGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_TAG);
  assert.strictEqual(headers['accept-language'], 'zh-cn');
});

test('越界权重整体删除', () => {
  const headers = h('en;q=2');
  const r = guard.applyAcceptLanguageGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.BAD_WEIGHT);
  assert.strictEqual(headers['accept-language'], undefined);
});

test('条目过多整体删除', () => {
  const headers = h(Array.from({ length: 12 }, (_, i) => 'l' + i).join(','));
  const r = guard.applyAcceptLanguageGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers['accept-language'], undefined);
});

test('超长头删除', () => {
  const headers = h('en,' + 'zh-CN;q=0.9,'.repeat(40));
  const r = guard.applyAcceptLanguageGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
});
