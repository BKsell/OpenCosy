'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./earlyhintguard');

test('缺头不改动', () => {
  const r = guard.applyEarlyHintGuard({});
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('preload 条目合规', () => {
  const headers = { link: '</app.css>; rel=preload; as=style' };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.changed, false);
});

test('明文 http 被拒', () => {
  const headers = { link: '<http://cdn.example.com/a.js>; rel=preload; as=script' };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.UNSAFE_URL);
  assert.strictEqual(headers.link, undefined);
});

test('缺 as 的 preload 被拒', () => {
  const headers = { link: '</app.js>; rel=preload' };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('控制字符直接删除', () => {
  const headers = { link: '</a>; rel=preload\u0000' };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.BAD_VALUE);
});

test('超长列表截断', () => {
  const entries = Array.from({ length: 12 }, (_, i) => `</s${i}.js>; rel=preload; as=script`);
  const headers = { link: entries.join(', ') };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.TOO_MANY);
  assert.strictEqual(headers.link.split(',').length, 8);
});

test('非法条目被剔除', () => {
  const headers = { link: '</ok.css>; rel=preload; as=style, not-a-link' };
  const r = guard.applyEarlyHintGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OK === r.reason ? guard.REASON.BAD_VALUE : r.reason);
  assert.strictEqual(headers.link, '</ok.css>; rel=preload; as=style');
});
