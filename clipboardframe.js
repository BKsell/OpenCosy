'use strict';

const boundary = require('./frameboundary');

const ACTION = { ALLOW: 'allow', WARN: 'warn', DENY: 'deny' };

const REASON = {
  OK: 'ok',
  MISSING_ORIGIN: 'missing-origin',
  CROSS_ORIGIN_FRAME: 'cross-origin-frame',
  TAB_INACTIVE: 'tab-inactive',
  WINDOW_UNFOCUSED: 'window-unfocused',
  OPAQUE_ORIGIN: 'opaque-origin',
  TOO_LARGE: 'too-large',
  HTML_PAYLOAD: 'html-payload',
  INSECURE_TRANSPORT: 'insecure-transport',
};

const MAX_CLIPBOARD_WRITE_BYTES = 1 << 20;
const MAX_CLIPBOARD_TEXT_CHARS = 1 << 20;

function payloadBytes(input) {
  if (Number.isFinite(input && input.bytes) && input.bytes >= 0) return input.bytes;
  const text = String((input && input.text) || '');
  return Buffer.byteLength(text, 'utf8');
}

function evaluateClipboardFrame(input = {}) {
  const frame = boundary.inspectFrame(input);
  const bytes = payloadBytes(input);
  const base = { bytes, frame };
  const blocking = boundary.blockingFrameReasons(frame);
  if (blocking.length > 0) {
    return Object.assign(base, {
      action: ACTION.DENY,
      reason: blocking[0] === 'missing-url' || blocking[0] === 'opaque-origin'
        ? REASON.OPAQUE_ORIGIN
        : blocking[0].replace(/-/g, '_').replace('_frame', '_frame'),
      detail: `剪贴板写入被拒绝: ${blocking.join(',')}`,
    });
  }
  if (bytes > MAX_CLIPBOARD_WRITE_BYTES) {
    return Object.assign(base, {
      action: ACTION.DENY, reason: REASON.TOO_LARGE,
      detail: `写入 ${bytes} 字节超过 1 MiB 上限`,
    });
  }
  if (input.html === true) {
    return Object.assign(base, {
      action: ACTION.WARN, reason: REASON.HTML_PAYLOAD,
      detail: '网页写入 HTML 剪贴板内容，可能携带不可见标记',
    });
  }
  if (frame.reasons.includes(boundary.FRAME_REASON.INSECURE_TRANSPORT)) {
    return Object.assign(base, {
      action: ACTION.WARN, reason: REASON.INSECURE_TRANSPORT,
      detail: '明文页面写入剪贴板，放行并留痕',
    });
  }
  return Object.assign(base, { action: ACTION.ALLOW, reason: REASON.OK, detail: '' });
}

function describeClipboardFrame(decision) {
  if (!decision || decision.reason === REASON.OK) return '剪贴板写入帧边界校验通过';
  return `${decision.reason}: ${decision.detail || ''}`.trim();
}

module.exports = {
  ACTION,
  REASON,
  MAX_CLIPBOARD_WRITE_BYTES,
  MAX_CLIPBOARD_TEXT_CHARS,
  payloadBytes,
  evaluateClipboardFrame,
  describeClipboardFrame,
};
