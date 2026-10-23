'use strict';

// capturehandleguard.test.js —— Capture Handle：跨站暴露 origin、handle 校验、条件聚焦、裁剪、通配消息。

const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('./capturehandleguard');
const { CaptureHandleGuard, CH_REASON, defaultCaptureHandlePolicy, regSite } = c;

function ctx(over) {
  return Object.assign({ origin: 'https://docs.internal.example.com' }, over || {});
}

test('同站暴露 origin 放行', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideExpose(ctx(), { exposeOrigin: true }, 'https://meet.example.com').decision, 'allow');
});

test('跨站暴露 origin 默认拒绝，permittedOrigins 放行', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideExpose(ctx(), { exposeOrigin: true }, 'https://meet.other.com').reason,
    CH_REASON.EXPOSE_ORIGIN_CROSS_SITE);
  const r = g.decideExpose(ctx(),
    { exposeOrigin: true, permittedOrigins: ['https://meet.other.com'] }, 'https://meet.other.com');
  assert.equal(r.decision, 'allow');
});

test('handle 超长/控制字符拒绝', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideExpose(ctx(), { handle: 'x'.repeat(200) }, 'https://meet.example.com').reason,
    CH_REASON.HANDLE_TOO_LONG);
  assert.equal(g.decideExpose(ctx(), { handle: 'a\nb' }, 'https://meet.example.com').reason,
    CH_REASON.HANDLE_CONTROL_CHAR);
});

test('条件聚焦/强制聚焦默认拒绝', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideFocus(ctx(), 'conditional-focus').reason, CH_REASON.CONDITIONAL_FOCUS_DISABLED);
  assert.equal(g.decideFocus(ctx(), 'focus-captured-tab').reason, CH_REASON.FOCUS_CAPTURED_TAB_DENIED);
  const pol = defaultCaptureHandlePolicy();
  pol.allowConditionalFocus = true;
  const g2 = new CaptureHandleGuard(pol);
  assert.equal(g2.decideFocus(ctx(), 'conditional-focus').decision, 'allow');
});

test('裁剪 zoom 默认拒绝，放开后允许', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideCropZoom(ctx()).reason, CH_REASON.ZOOM_NOT_ALLOWED);
  const pol = defaultCaptureHandlePolicy();
  pol.allowZoomCrop = true;
  const g2 = new CaptureHandleGuard(pol);
  assert.equal(g2.decideCropZoom(ctx()).decision, 'allow');
});

test('capturehandle 通配 postMessage 拒绝', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideMessage({ targetOrigin: '*' }).reason, CH_REASON.POSTMESSAGE_WILDCARD);
  assert.equal(g.decideMessage({ targetOrigin: 'https://meet.example.com' }).decision, 'allow');
});

test('非 https / 坏上下文拒绝', () => {
  const g = new CaptureHandleGuard();
  assert.equal(g.decideExpose({ origin: 'http://x' }, {}, 'https://meet.example.com').reason, CH_REASON.INSECURE_ORIGIN);
  assert.equal(g.decideExpose(null, {}, 'x').reason, CH_REASON.BAD_CONTEXT);
  assert.equal(g.decideFocus(null, 'conditional-focus').reason, CH_REASON.BAD_CONTEXT);
  assert.equal(g.decideCropZoom(null).reason, CH_REASON.BAD_CONTEXT);
});

test('regSite 纯字符', () => {
  assert.equal(regSite('https://a.b.example.com:8443/x'), 'example.com');
});
