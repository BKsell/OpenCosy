'use strict';

// richclipguard.test.js —— 富剪贴板：手势/可见、unsanitized HTML、危险片段、MIME、体积、频率。

const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('./richclipguard');
const { RichClipGuard, RC_REASON, containsDangerousHtml, defaultRichClipPolicy } = c;

let now = 1_700_000_000_000;
const clock = () => now;
function ctx(over) { return Object.assign({ origin: 'https://editor.example.com', userGesture: true, visible: true }, over || {}); }

test('纯文本粘贴放行', () => {
  const g = new RichClipGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), { type: 'text/plain', text: 'hello' }).decision, 'allow');
});

test('无手势/不可见/非 https 拒绝', () => {
  const g = new RichClipGuard(undefined, clock);
  assert.equal(g.decideRead(ctx({ userGesture: false }), { type: 'text/plain' }).reason, RC_REASON.NO_GESTURE);
  assert.equal(g.decideRead(ctx({ visible: false }), { type: 'text/plain' }).reason, RC_REASON.NOT_VISIBLE);
  assert.equal(g.decideRead(ctx({ origin: 'http://x' }), { type: 'text/plain' }).reason, RC_REASON.INSECURE_ORIGIN);
});

test('请求 unsanitized html 默认拒绝', () => {
  const g = new RichClipGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), { type: 'text/html', text: '<b>x</b>' }, { unsanitized: 'html' }).reason,
    RC_REASON.UNSANITIZED_HTML);
});

test('净化模式下含脚本的 HTML 被审计', () => {
  const g = new RichClipGuard(undefined, clock);
  // 默认 sanitizeHtmlOnRead=true：危险片段在 sanitized 读取下不直接拒绝（交上层净化），放行。
  assert.equal(g.decideRead(ctx(), { type: 'text/html', text: '<p onclick="x()">hi</p>' }).decision, 'allow');
  // 关闭净化时，危险片段直接拒绝。
  const pol = defaultRichClipPolicy();
  pol.sanitizeHtmlOnRead = false;
  const g2 = new RichClipGuard(pol, clock);
  assert.equal(g2.decideRead(ctx(), { type: 'text/html', text: '<img src=x onerror=alert(1)>' }).reason,
    RC_REASON.SCRIPT_IN_HTML);
});

test('未知 MIME 拒绝', () => {
  const g = new RichClipGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), { type: 'application/x-msdownload' }).reason, RC_REASON.UNKNOWN_MIME);
});

test('超大图片/文本拒绝', () => {
  const g = new RichClipGuard(undefined, clock);
  assert.equal(g.decideRead(ctx(), { type: 'image/png', sizeBytes: 50 * 1024 * 1024 }).reason, RC_REASON.PAYLOAD_TOO_LARGE);
  assert.equal(g.decideRead(ctx(), { type: 'text/plain', text: 'x'.repeat(2 * 1024 * 1024) }).reason, RC_REASON.PAYLOAD_TOO_LARGE);
});

test('读取频率上限', () => {
  const pol = defaultRichClipPolicy();
  pol.maxReadsPerMinute = 2;
  const g = new RichClipGuard(pol, clock);
  assert.equal(g.decideReadText(ctx()).decision, 'allow');
  assert.equal(g.decideReadText(ctx()).decision, 'allow');
  assert.equal(g.decideReadText(ctx()).reason, RC_REASON.RATE_LIMIT);
});

test('read 关闭时拒绝', () => {
  const pol = defaultRichClipPolicy();
  pol.allowRead = false;
  const g = new RichClipGuard(pol, clock);
  assert.equal(g.decideReadText(ctx()).reason, RC_REASON.READ_DISABLED);
});

test('containsDangerousHtml 纯字符', () => {
  assert.equal(containsDangerousHtml('<SCRIPT>'), '<script');
  assert.equal(containsDangerousHtml('<b>ok</b>'), '');
});
