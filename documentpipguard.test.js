'use strict';

// documentpipguard.test.js —— Document PiP：手势/可见、尺寸、屏幕占比、copyVideo、窗内高敏能力、每标签一窗。

const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('./documentpipguard');
const { DocumentPipGuard, DP_REASON, defaultDocumentPipPolicy } = d;

function ctx(over) {
  return Object.assign({ origin: 'https://video.example.com', userGesture: true, visible: true, tabKey: 't1', screenWidth: 1920, screenHeight: 1080 }, over || {});
}

test('合规小窗放行', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx(), { width: 400, height: 260 }).decision, 'allow');
});

test('无手势/隐藏打开拒绝', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx({ userGesture: false }), {}).reason, DP_REASON.NO_GESTURE);
  assert.equal(g.decideOpen(ctx({ visible: false }), {}).reason, DP_REASON.OPEN_WHEN_HIDDEN);
});

test('尺寸非法/超限拒绝', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx(), { width: -1 }).reason, DP_REASON.DIMENSION_BAD);
  assert.equal(g.decideOpen(ctx(), { width: 800 }).reason, DP_REASON.WINDOW_TOO_LARGE);
  assert.equal(g.decideOpen(ctx(), { height: 900 }).reason, DP_REASON.WINDOW_TOO_LARGE);
});

test('相对屏幕占比超限拒绝', () => {
  const g = new DocumentPipGuard();
  // 500 绝对宽度通过，但相对 800 宽屏幕 500 > 400。
  assert.equal(g.decideOpen(ctx({ screenWidth: 800 }), { width: 500, height: 300 }).reason, DP_REASON.WINDOW_TOO_LARGE);
});

test('copyVideo 默认拒绝', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx(), { copyVideo: true }).reason, DP_REASON.COPY_VIDEO_DISABLED);
});

test('窗内申请相机/支付等高敏能力拒绝', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx(), { requestedFeatures: ['camera'] }).reason, DP_REASON.SENSITIVE_FEATURE_IN_PIP);
  assert.equal(g.decideOpen(ctx(), { requestedFeatures: ['payment'] }).reason, DP_REASON.SENSITIVE_FEATURE_IN_PIP);
});

test('每标签仅一窗，关闭后可再开', () => {
  const g = new DocumentPipGuard();
  assert.equal(g.decideOpen(ctx(), {}).decision, 'allow');
  assert.equal(g.decideOpen(ctx(), {}).reason, DP_REASON.TOO_MANY_WINDOWS);
  g.close(ctx());
  assert.equal(g.decideOpen(ctx(), {}).decision, 'allow');
});

test('放开 copyVideo 后允许', () => {
  const pol = defaultDocumentPipPolicy();
  pol.blockCopyVideo = false;
  const g = new DocumentPipGuard(pol);
  assert.equal(g.decideOpen(ctx(), { copyVideo: true }).decision, 'allow');
});
