'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const guard = require('./clipboardframe');

const SITE = 'https://app.test/editor';

test('正常顶层写入放行', () => {
  const decision = guard.evaluateClipboardFrame({ requestUrl: SITE, topUrl: SITE, text: 'hello' });
  assert.equal(decision.action, 'allow');
  assert.equal(decision.reason, 'ok');
  assert.equal(decision.bytes, 5);
});

test('超限写入被拒绝', () => {
  const decision = guard.evaluateClipboardFrame({
    requestUrl: SITE,
    topUrl: SITE,
    bytes: guard.MAX_CLIPBOARD_WRITE_BYTES + 1,
  });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'too-large');
});

test('跨源子框架不能写剪贴板', () => {
  const decision = guard.evaluateClipboardFrame({
    requestUrl: 'https://ads.test/frame',
    topUrl: SITE,
    isMainFrame: false,
  });
  assert.equal(decision.action, 'deny');
  assert.match(decision.detail, /cross-origin-frame/);
});

test('后台标签写入被拒绝', () => {
  const decision = guard.evaluateClipboardFrame({ requestUrl: SITE, topUrl: SITE, tabActive: false });
  assert.equal(decision.action, 'deny');
  assert.match(decision.detail, /tab-inactive/);
});

test('HTML 载荷只告警', () => {
  const decision = guard.evaluateClipboardFrame({ requestUrl: SITE, topUrl: SITE, html: true, text: 'x' });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'html-payload');
});

test('明文站点的写入只告警', () => {
  const decision = guard.evaluateClipboardFrame({
    requestUrl: 'http://app.test/',
    topUrl: 'http://app.test/',
    text: 'x',
  });
  assert.equal(decision.action, 'warn');
  assert.equal(decision.reason, 'insecure-transport');
});

test('不透明 origin 拒绝', () => {
  const decision = guard.evaluateClipboardFrame({ requestUrl: 'blob:https://app.test/1', topUrl: SITE });
  assert.equal(decision.action, 'deny');
  assert.equal(decision.reason, 'opaque-origin');
});

test('payloadBytes 支持文本与显式字节数', () => {
  assert.equal(guard.payloadBytes({ text: '中文' }), Buffer.byteLength('中文', 'utf8'));
  assert.equal(guard.payloadBytes({ bytes: 12 }), 12);
  assert.equal(guard.payloadBytes({ bytes: -1, text: 'ab' }), 2);
  assert.equal(guard.MAX_CLIPBOARD_TEXT_CHARS, 1 << 20);
});

test('describe 输出通过文案', () => {
  assert.equal(guard.describeClipboardFrame({ reason: 'ok' }), '剪贴板写入帧边界校验通过');
  assert.match(guard.describeClipboardFrame({ reason: 'too-large', detail: 'x' }), /too-large/);
});
