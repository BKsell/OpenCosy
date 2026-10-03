'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const g = require('./inputguard');

test('asString 基本类型与长度', () => {
  assert.equal(g.asString('hi').ok, true);
  assert.equal(g.asString(123).ok, false);
  assert.equal(g.asString('x', { max: 2 }).ok, true);
  assert.equal(g.asString('xyz', { max: 2 }).reason, g.REASON.TOO_LONG);
  assert.equal(g.asString('a\x00b').reason, g.REASON.CONTROL_CHAR);
  assert.equal(g.asString('  x  ', { trim: true }).value, 'x');
  assert.equal(g.asString('', { allowEmpty: false }).reason, g.REASON.EMPTY);
  // 普通换行在 rejectControl 下也判负（IPC 标识 / 路径不应含换行）。
  assert.equal(g.asString('a\nb').ok, false);
  // 显式放开控制字符时通过（需要保留多行文本的通道自行承担）。
  assert.equal(g.asString('a\nb', { rejectControl: false }).ok, true);
});

test('asBoolean 拒绝字符串伪装', () => {
  assert.equal(g.asBoolean(true).value, true);
  assert.equal(g.asBoolean(false).ok, true);
  assert.equal(g.asBoolean('false').ok, false);
  assert.equal(g.asBoolean(0).ok, false);
});

test('asInteger 安全整数与区间', () => {
  assert.equal(g.asInteger(5).ok, true);
  assert.equal(g.asInteger(5, { min: 1, max: 10 }).ok, true);
  assert.equal(g.asInteger(0, { min: 1 }).ok, false);
  assert.equal(g.asInteger(11, { max: 10 }).ok, false);
  assert.equal(g.asInteger(1.5).ok, false);
  assert.equal(g.asInteger('5').ok, false);
  assert.equal(g.asInteger(NaN).ok, false);
  assert.equal(g.asInteger(Infinity).ok, false);
});

test('isPlainObject / asPlainObject', () => {
  assert.equal(g.isPlainObject({}), true);
  assert.equal(g.isPlainObject(Object.create(null)), true);
  assert.equal(g.isPlainObject([]), false);
  assert.equal(g.isPlainObject(null), false);
  assert.equal(g.isPlainObject(new Date()), false);
  assert.equal(g.asPlainObject({ a: 1 }).ok, true);
});

test('asArray 类型与项数', () => {
  assert.equal(g.asArray([1, 2]).ok, true);
  assert.equal(g.asArray('x').ok, false);
  assert.equal(g.asArray([1], { maxItems: 1 }).ok, true);
  assert.equal(g.asArray([1, 2], { maxItems: 1 }).reason, g.REASON.TOO_MANY_ITEMS);
});

test('asUrl 协议与畸形', () => {
  assert.equal(g.asUrl('https://a.com').ok, true);
  assert.equal(g.asUrl('http://a.com/x').value, 'http://a.com/x');
  assert.equal(g.asUrl('javascript:alert(1)').reason, g.REASON.BAD_SCHEME);
  assert.equal(g.asUrl('not a url').reason, g.REASON.BAD_URL);
  assert.equal(g.asUrl(42).reason, g.REASON.BAD_URL);
  assert.equal(g.asUrl('https://a.com/a\nb').reason, g.REASON.CONTROL_CHAR);
  const custom = g.asUrl('cosy://settings', { schemes: ['cosy:'] });
  assert.equal(custom.ok, true);
});

test('measureObject 深度越界', () => {
  let deep = { a: 1 };
  for (let i = 0; i < 40; i++) deep = { a: deep };
  const r = g.measureObject(deep, { maxDepth: 32 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, g.REASON.TOO_DEEP);
});

test('measureObject 键数越界', () => {
  const o = {};
  for (let i = 0; i < 100; i++) o['k' + i] = i;
  const r = g.measureObject(o, { maxKeys: 50 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, g.REASON.TOO_MANY_KEYS);
});

test('measureObject 体量越界', () => {
  const r = g.measureObject({ s: 'x'.repeat(1000) }, { maxBytes: 100 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, g.REASON.TOO_LONG);
});

test('measureObject 拒绝函数等非 JSON 值', () => {
  const r = g.measureObject({ fn: () => {} });
  assert.equal(r.ok, false);
  assert.equal(r.reason, g.REASON.NOT_OBJECT);
});

test('measureObject 正常对象通过', () => {
  const r = g.measureObject({ a: 1, b: 'x', c: [1, 2, { d: true }] });
  assert.equal(r.ok, true);
  assert.ok(r.keys >= 3);
});

test('assertShape 成功收敛字段', () => {
  const r = g.assertShape(
    { name: 'abc', count: 3, extra: 'ignored' },
    { name: v => g.asString(v, { max: 10 }), count: v => g.asInteger(v, { min: 0 }) });
  assert.equal(r.ok, true);
  assert.deepEqual(r.value, { name: 'abc', count: 3 });
});

test('assertShape 报告错误字段', () => {
  const r = g.assertShape(
    { name: 123, count: 3 },
    { name: v => g.asString(v), count: v => g.asInteger(v) });
  assert.equal(r.ok, false);
  assert.equal(r.field, 'name');
  assert.equal(r.reason, g.REASON.NOT_STRING);
});

test('assertShape 非对象输入', () => {
  const r = g.assertShape(null, { x: v => g.asString(v) });
  assert.equal(r.ok, false);
  assert.equal(r.reason, g.REASON.NOT_OBJECT);
});
