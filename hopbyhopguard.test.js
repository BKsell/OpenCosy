'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const guard = require('./hopbyhopguard');

test('空对象返回 missing', () => {
  const r = guard.applyHopByHopGuard({});
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.MISSING);
});

test('普通响应头不改动', () => {
  const headers = { 'content-type': ['text/html'], 'cache-control': ['no-store'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.strictEqual(r.reason, guard.REASON.OK);
  assert.deepStrictEqual(r.stripped, []);
});

test('Proxy-Connection 被剥离', () => {
  const headers = { 'Proxy-Connection': ['keep-alive'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.HOP_BY_HOP);
  assert.strictEqual(headers['Proxy-Connection'], undefined);
});

test('Keep-Alive 与 Trailer 被剥离', () => {
  const headers = { 'keep-alive': ['timeout=5'], trailer: ['X-Checksum'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.stripped.sort(), ['keep-alive', 'trailer']);
});

test('Upgrade 只在非 101 场景剥离', () => {
  const headers = { upgrade: ['h2c'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(headers.upgrade, undefined);
});

test('Connection 声明的自定义头被剥离', () => {
  const headers = { Connection: ['X-Internal, close'], 'x-internal': ['1'], 'x-keep': ['2'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.strictEqual(r.reason, guard.REASON.CONNECTION_TOKEN);
  assert.strictEqual(headers['x-internal'], undefined);
  assert.deepStrictEqual(headers['x-keep'], ['2']);
  assert.strictEqual(headers.Connection, undefined);
});

test('Connection 仅含 keep-alive 仍被移除', () => {
  const headers = { connection: ['keep-alive'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(headers.connection, ['keep-alive']);
});

test('超长 Connection 直接剥离', () => {
  const headers = { connection: ['x'.repeat(300)] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.reason, guard.REASON.OVERLONG);
  assert.strictEqual(headers.connection, undefined);
});

test('parseConnectionTokens 忽略停止词', () => {
  assert.deepStrictEqual(guard.parseConnectionTokens('close, Keep-Alive, X-A'), ['x-a']);
});

test('多个逐跳头一次性清理', () => {
  const headers = { te: ['trailers'], trailer: ['x'], 'proxy-authorization': ['Basic x'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.stripped.length, 3);
  assert.strictEqual(Object.keys(headers).length, 0);
});

test('大小写混合键名仍被清理', () => {
  const headers = { 'PROXY-AUTHENTICATE': ['Basic realm=x'], 'TE': ['gzip'] };
  const r = guard.applyHopByHopGuard(headers);
  assert.strictEqual(r.changed, true);
  assert.deepStrictEqual(r.stripped.sort(), ['proxy-authenticate', 'te']);
});

test('describeReason 对未知原因回退', () => {
  assert.strictEqual(typeof guard.describeReason('what'), 'string');
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
