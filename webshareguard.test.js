'use strict';

// webshareguard.test.js —— Web Share：手势/可见、scheme、URL/文本伪装、体积、可执行文件、文件数、频率。

const test = require('node:test');
const assert = require('node:assert/strict');
const w = require('./webshareguard');
const { WebShareGuard, WS_REASON, extOf, defaultWebSharePolicy } = w;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://article.example.com', userGesture: true, visible: true }, over || {}); }
function data(over) { return Object.assign({ title: 't', text: 'look', url: 'https://article.example.com/x' }, over || {}); }

test('合规分享放行', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx(), data()).decision, 'allow');
});

test('空分享拒绝', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx(), {}).reason, WS_REASON.EMPTY_SHARE);
});

test('无手势/不可见/非 https 拒绝', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx({ userGesture: false }), data()).reason, WS_REASON.NO_GESTURE);
  assert.equal(g.decideShare(ctx({ visible: false }), data()).reason, WS_REASON.NOT_VISIBLE);
  assert.equal(g.decideShare(ctx({ origin: 'http://x' }), data()).reason, WS_REASON.INSECURE_ORIGIN);
});

test('javascript/data/file scheme 拒绝', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx(), data({ url: 'javascript:alert(1)' })).reason, WS_REASON.BAD_URL_SCHEME);
  assert.equal(g.decideShare(ctx(), data({ url: 'data:text/html,x' })).reason, WS_REASON.BAD_URL_SCHEME);
  assert.equal(g.decideShare(ctx(), data({ url: 'file:///c/x' })).reason, WS_REASON.BAD_URL_SCHEME);
});

test('要求 URL 出现在文本时不一致拒绝', () => {
  const pol = defaultWebSharePolicy();
  pol.requireUrlInText = true;
  const g = new WebShareGuard(pol, clock);
  assert.equal(g.decideShare(ctx(), data({ text: 'totally unrelated' })).reason, WS_REASON.URL_TEXT_MISMATCH);
});

test('超大文本拒绝', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx(), data({ text: 'x'.repeat(5000) })).reason, WS_REASON.TEXT_TOO_LARGE);
});

test('可执行文件类型拒绝', () => {
  const g = new WebShareGuard(undefined, clock);
  assert.equal(g.decideShare(ctx(), { files: [{ name: 'payload.exe', sizeBytes: 10 }] }).reason, WS_REASON.FILE_TYPE_BLOCKED);
  assert.equal(g.decideShare(ctx(), { files: [{ name: 'run.sh', sizeBytes: 10 }] }).reason, WS_REASON.FILE_TYPE_BLOCKED);
});

test('文件数/单文件大小上限', () => {
  const g = new WebShareGuard(undefined, clock);
  const many = [];
  for (let i = 0; i < 5; i++) many.push({ name: 'p' + i + '.png', sizeBytes: 10 });
  assert.equal(g.decideShare(ctx(), { files: many }).reason, WS_REASON.TOO_MANY_FILES);
  assert.equal(g.decideShare(ctx(), { files: [{ name: 'big.png', sizeBytes: 99 * 1024 * 1024 }] }).reason, WS_REASON.FILE_TOO_LARGE);
});

test('分享频率上限', () => {
  const pol = defaultWebSharePolicy();
  pol.maxSharesPerMinute = 2;
  const g = new WebShareGuard(pol, clock);
  assert.equal(g.decideShare(ctx(), data()).decision, 'allow');
  assert.equal(g.decideShare(ctx(), data()).decision, 'allow');
  assert.equal(g.decideShare(ctx(), data()).reason, WS_REASON.RATE_LIMIT);
});

test('extOf 纯字符', () => {
  assert.equal(extOf('Photo.PNG'), 'png');
});
