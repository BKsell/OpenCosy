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
};

const FRAME_TO_REASON = {
  'missing-url': REASON.MISSING_URL,
  'opaque-origin': REASON.OPAQUE_ORIGIN,
  'cross-origin-frame': REASON.CROSS_ORIGIN_FRAME,
  'tab-inactive': REASON.TAB_INACTIVE,
  'window-unfocused': REASON.WINDOW_UNFOCUSED,
  'insecure-transport': REASON.INSECURE_TRANSPORT,
};

function evaluatePointerLockFrame(input = {}) {
  const frame = boundary.inspectFrame(input);
  const blocking = boundary.blockingFrameReasons(frame);
  if (blocking.length > 0) {
    return {
      action: ACTION.DENY,
      reason: FRAME_TO_REASON[blocking[0]] || REASON.MISSING_URL,
      detail: `指针锁定请求被拒绝: ${blocking.join(',')}`,
      frame,
    };
  }
  if (frame.reasons.includes(boundary.FRAME_REASON.INSECURE_TRANSPORT)) {
    return {
      action: ACTION.WARN,
      reason: REASON.INSECURE_TRANSPORT,
      detail: '明文页面请求指针锁定，放行并留痕',
      frame,
    };
  }
  return { action: ACTION.ALLOW, reason: REASON.OK, detail: '', frame };
}

function describePointerLockFrame(decision) {
  if (!decision || decision.reason === REASON.OK) return '指针锁定帧边界校验通过';
  return `${decision.reason}: ${decision.detail || ''}`.trim();
}

module.exports = { ACTION, REASON, evaluatePointerLockFrame, describePointerLockFrame };
