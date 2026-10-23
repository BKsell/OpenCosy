'use strict';

// sharedstorageguard.test.js —— Shared Storage：三方上下文、key、value、append/worklet/selectURL、配额。

const test = require('node:test');
const assert = require('node:assert/strict');
const s = require('./sharedstorageguard');
const { SharedStorageGuard, SS_REASON, defaultSharedStoragePolicy } = s;

function ctx(over) {
  return Object.assign({ origin: 'https://pub.example.com', isTopFrame: true }, over || {});
}

test('顶层 set 放行', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'set', 'k', 'v').decision, 'allow');
});

test('三方上下文默认拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx({ isTopFrame: false }), 'set', 'k', 'v').reason, SS_REASON.THIRD_PARTY_CONTEXT);
});

test('非 https 拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx({ origin: 'http://x' }), 'set', 'k', 'v').reason, SS_REASON.INSECURE_ORIGIN);
});

test('append 默认拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'append', 'k', 'v').reason, SS_REASON.APPEND_NOT_ALLOWED);
});

test('run/selectURL 默认拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'run').reason, SS_REASON.WORKLET_NOT_ALLOWED);
  assert.equal(g.decide(ctx(), 'selectURL').reason, SS_REASON.SELECT_URL_NOT_ALLOWED);
});

test('selectURL 选项过多拒绝', () => {
  const pol = defaultSharedStoragePolicy();
  pol.allowSelectURL = true;
  const g = new SharedStorageGuard(pol);
  const urls = [];
  for (let i = 0; i < 12; i++) urls.push({ url: 'https://e' + i + '.test' });
  assert.equal(g.decide(ctx(), 'selectURL', null, null, { urls }).reason, SS_REASON.TOO_MANY_OPTIONS);
  assert.equal(g.decide(ctx(), 'selectURL', null, null, { urls: urls.slice(0, 4) }).decision, 'allow');
});

test('非法/超长/控制字符 key 拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'set', '', 'v').reason, SS_REASON.BAD_KEY);
  assert.equal(g.decide(ctx(), 'set', 'k'.repeat(200), 'v').reason, SS_REASON.KEY_TOO_LONG);
  assert.equal(g.decide(ctx(), 'set', 'a\nb', 'v').reason, SS_REASON.KEY_CONTROL_CHAR);
});

test('超大 value 拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'set', 'k', 'x'.repeat(2000)).reason, SS_REASON.VALUE_TOO_LARGE);
});

test('写次数配额耗尽拒绝', () => {
  const pol = defaultSharedStoragePolicy();
  pol.maxWritesPerOrigin = 3;
  const g = new SharedStorageGuard(pol);
  for (let i = 0; i < 3; i++) assert.equal(g.decide(ctx(), 'set', 'k' + i, 'v').decision, 'allow');
  assert.equal(g.decide(ctx(), 'set', 'k3', 'v').reason, SS_REASON.RATE_LIMIT);
});

test('写字节配额耗尽拒绝', () => {
  const pol = defaultSharedStoragePolicy();
  pol.maxWriteBytesPerOrigin = 10;
  const g = new SharedStorageGuard(pol);
  assert.equal(g.decide(ctx(), 'set', 'k', 'aaaaaa').decision, 'allow'); // 6
  assert.equal(g.decide(ctx(), 'set', 'k2', 'bbbbbb').reason, SS_REASON.RATE_LIMIT); // 再 6 超 10
  g.resetForOrigin(ctx().origin);
  assert.equal(g.decide(ctx(), 'set', 'k', 'a').decision, 'allow');
});

test('未知 op 拒绝', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'explode', 'k', 'v').reason, SS_REASON.API_DISABLED);
});

test('delete 默认允许', () => {
  const g = new SharedStorageGuard();
  assert.equal(g.decide(ctx(), 'delete', 'k').decision, 'allow');
});
