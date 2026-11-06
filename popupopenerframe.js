'use strict';

const boundary = require('./frameboundary');

const ACTION = { ALLOW: 'allow', WARN: 'warn', DENY: 'deny' };

const REASON = {
  OK: 'ok',
  MISSING_URL: 'missing-url',
  OPAQUE_ORIGIN: 'opaque-origin',
  CROSS_ORIGIN_FRAME: 'cross-origin-frame',
  TAB_INACTIVE: 'tab-inactive',
  WINDOW_UNFOCUSED: 'window-unfocused',
  INSECURE_TRANSPORT: 'insecure-transport',
  TOO_MANY_FRAMES: 'too-many-frames',
};

const MAX_POPUP_FRAME_DEPTH = 3;

function evaluatePopupFrame(input = {}) {
  const frame = boundary.inspectFrame(input);
  const depth = Number.isFinite(input.frameDepth) ? input.frameDepth : 0;
  if (depth > MAX_POPUP_FRAME_DEPTH) {
    return {
      action: ACTION.DENY,
      reason: REASON.TOO_MANY_FRAMES,
      detail: `弹窗请求来自 ${depth} 层嵌套框架，超过 ${MAX_POPUP_FRAME_DEPTH} 层上限`,
      frame,
    };
  }
  const blocking = boundary.blockingFrameReasons(frame);
  if (blocking.length > 0) {
    const reason = blocking[0] === 'missing-url'
      ? REASON.MISSING_URL
      : blocking[0] === 'opaque-origin'
        ? REASON.OPAQUE_ORIGIN
        : blocking[0] === 'cross-origin-frame'
          ? REASON.CROSS_ORIGIN_FRAME
          : blocking[0] === 'tab-inactive'
            ? REASON.TAB_INACTIVE
            : REASON.WINDOW_UNFOCUSED;
    return { action: ACTION.DENY, reason, detail: `弹窗请求被拒绝: ${blocking.join(',')}`, frame };
  }
  if (frame.reasons.includes(boundary.FRAME_REASON.INSECURE_TRANSPORT)) {
    return {
      action: ACTION.WARN, reason: REASON.INSECURE_TRANSPORT,
      detail: '明文页面申请弹窗权限，放行并留痕', frame,
    };
  }
  return { action: ACTION.ALLOW, reason: REASON.OK, detail: '', frame };
}

function describePopupFrame(decision) {
  if (!decision || decision.reason === REASON.OK) return '弹窗帧边界校验通过';
  return `${decision.reason}: ${decision.detail || ''}`.trim();
}

module.exports = { ACTION, REASON, MAX_POPUP_FRAME_DEPTH, evaluatePopupFrame, describePopupFrame };
