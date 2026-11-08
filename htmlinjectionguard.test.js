'use strict';

const test = require('node:test');
const assert = require('node:assert');
const guard = require('./htmlinjectionguard');

test('纯文本通过', () => {
  const r = guard.applyHtmlInjectionGuard('页面加载失败，请稍后重试');
  assert.strictEqual(r.changed, false);
  assert.deepStrictEqual(r.matches, []);
});

test('允许标记模式跳过检查', () => {
  const r = guard.applyHtmlInjectionGuard('<b>ok</b>', { allowMarkup: true });
  assert.strictEqual(r.changed, false);
});

test('script 标签被拒', () => {
  const r = guard.inspectText('<script>steal()</script>');
  assert.strictEqual(r.reason, guard.REASON.SCRIPT_TAG);
});

test('iframe 标签被拒', () => {
  const r = guard.inspectText('<iframe src="https://evil.example.com"></iframe>');
  assert.strictEqual(r.reason, guard.REASON.IFRAME_TAG);
});

test('svg 标签被拒', () => {
  const r = guard.inspectText('<svg onload=alert(1)>');
  assert.strictEqual(r.reason, guard.REASON.SVG_TAG);
});

test('事件属性被拒', () => {
  const r = guard.inspectText('<img src=x onerror=alert(1)>');
  assert.strictEqual(r.reason, guard.REASON.EVENT_HANDLER);
});

test('javascript 伪协议被拒', () => {
  const r = guard.inspectText('javascript:alert(1)');
  assert.strictEqual(r.reason, guard.REASON.JAVASCRIPT_URI);
});

test('data:text/html 被拒', () => {
  const r = guard.inspectText('data:text/html;base64,PHNjcmlwdD4=');
  assert.strictEqual(r.reason, guard.REASON.DATA_HTML);
});

test('样式表达式被拒', () => {
  const r = guard.inspectText('background:expression(alert(1))');
  assert.strictEqual(r.reason, guard.REASON.STYLE_EXPRESSION);
});

test('空字节被拒', () => {
  const r = guard.inspectText('abc\u0000def');
  assert.strictEqual(r.reason, guard.REASON.NUL_BYTE);
});

test('空文本被拒', () => {
  const r = guard.inspectText('');
  assert.strictEqual(r.reason, guard.REASON.EMPTY);
});

test('超长文本被拒', () => {
  const r = guard.inspectText('a'.repeat(guard.MAX_CHARS + 1));
  assert.strictEqual(r.reason, guard.REASON.TOO_LARGE);
});

test('描述文本覆盖所有原因', () => {
  for (const reason of Object.values(guard.REASON)) {
    assert.strictEqual(typeof guard.describeReason(reason), 'string');
  }
});
