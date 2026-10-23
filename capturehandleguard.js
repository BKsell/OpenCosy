'use strict';

// capturehandleguard.js ——屏幕分享 Capture Handle / Conditional Focus 安全裁决内核。
//
// 威胁模型：
//   1. getDisplayMedia 后，捕获方标签可通过 Capture Handle 读取被捕获标签的 origin/handle，
//      跨源识别用户正在展示的内部系统（银行、后台、病历），做场景指纹；
//   2. captureAll 暴露 origin 让会议页面记录与会者切到了哪个内网域名；
//   3. Conditional Focus（focusOptions / focusCapturedTab）可在分享时强行把被捕获标签拉到
//      前台，配合诱导实现焦点劫持/输入注入落点切换；
//   4. 被捕获方用 capturehandle 事件向捕获方 postMessage，通道不受同源约束，可泄漏数据；
//   5. zoom/裁剪用 captureController 读到边界坐标做布局推断。
//
// 纯逻辑：分别裁决"被捕获方是否暴露 handle"与"捕获方是否允许条件聚焦"。

const CH_ALLOW = 'allow';
const CH_DENY = 'deny';

const CH_REASON = Object.freeze({
  BAD_CONTEXT: 'ch-bad-context',
  INSECURE_ORIGIN: 'ch-insecure-origin',
  EXPOSE_ORIGIN_CROSS_SITE: 'ch-expose-origin-cross-site',
  HANDLE_TOO_LONG: 'ch-handle-too-long',
  HANDLE_CONTROL_CHAR: 'ch-handle-control-char',
  CONDITIONAL_FOCUS_DISABLED: 'ch-conditional-focus-disabled',
  FOCUS_CAPTURED_TAB_DENIED: 'ch-focus-captured-tab-denied',
  POSTMESSAGE_WILDCARD: 'ch-postmessage-wildcard',
  ZOOM_NOT_ALLOWED: 'ch-zoom-not-allowed',
});

const CH_MAX_HANDLE_BYTES = 128;

function defaultCaptureHandlePolicy() {
  return {
    requireHttps: true,
    exposeOriginOnlySameSite: true,
    maxHandleBytes: CH_MAX_HANDLE_BYTES,
    allowConditionalFocus: false,
    allowFocusCapturedTab: false,
    allowZoomCrop: false,
    requireExplicitPostMessageTarget: true,
  };
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}
function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}
function regSite(origin) {
  if (typeof origin !== 'string') return '';
  const i = origin.indexOf('://');
  if (i <= 0) return '';
  let rest = origin.slice(i + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  const labels = rest.toLowerCase().split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : rest.toLowerCase();
}

class CaptureHandleGuard {
  constructor(policy) {
    this.policy = policy || defaultCaptureHandlePolicy();
  }

  // decideExpose 裁决被捕获方 setCaptureHandleConfig({handle, exposeOrigin, permittedOrigins})。
  decideExpose(ctx, config, captureOrigin) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: CH_DENY, reason: CH_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: CH_DENY, reason: CH_REASON.INSECURE_ORIGIN };
    const cfg = config && typeof config === 'object' ? config : {};

    if (cfg.exposeOrigin === true && pol.exposeOriginOnlySameSite) {
      const mine = regSite(ctx.origin);
      const theirs = regSite(captureOrigin);
      const permitted = Array.isArray(cfg.permittedOrigins) ? cfg.permittedOrigins : [];
      const ok = theirs && (mine === theirs || permitted.some((o) => regSite(o) === theirs));
      if (!ok) return { decision: CH_DENY, reason: CH_REASON.EXPOSE_ORIGIN_CROSS_SITE, captureSite: theirs };
    }

    if (typeof cfg.handle === 'string') {
      if (byteLen(cfg.handle) > pol.maxHandleBytes) return { decision: CH_DENY, reason: CH_REASON.HANDLE_TOO_LONG };
      if (hasControlChar(cfg.handle)) return { decision: CH_DENY, reason: CH_REASON.HANDLE_CONTROL_CHAR };
    }
    return { decision: CH_ALLOW, reason: '' };
  }

  // decideFocus 裁决捕获方条件聚焦/强制聚焦被捕获标签。
  decideFocus(ctx, mode) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: CH_DENY, reason: CH_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: CH_DENY, reason: CH_REASON.INSECURE_ORIGIN };
    if (mode === 'conditional-focus' && !pol.allowConditionalFocus) {
      return { decision: CH_DENY, reason: CH_REASON.CONDITIONAL_FOCUS_DISABLED };
    }
    if (mode === 'focus-captured-tab' && !pol.allowFocusCapturedTab) {
      return { decision: CH_DENY, reason: CH_REASON.FOCUS_CAPTURED_TAB_DENIED };
    }
    return { decision: CH_ALLOW, reason: '' };
  }

  // decideCropZoom 裁决 RestrictionTarget 裁剪/zoom 操纵。
  decideCropZoom(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') {
      return { decision: CH_DENY, reason: CH_REASON.BAD_CONTEXT };
    }
    if (!pol.allowZoomCrop) return { decision: CH_DENY, reason: CH_REASON.ZOOM_NOT_ALLOWED };
    return { decision: CH_ALLOW, reason: '' };
  }

  // decideMessage 裁决被捕获方→捕获方的 capturehandle 消息。
  decideMessage(message) {
    if (this.policy.requireExplicitPostMessageTarget &&
        (!message || message.targetOrigin === '*' || message.targetOrigin === undefined)) {
      return { decision: CH_DENY, reason: CH_REASON.POSTMESSAGE_WILDCARD };
    }
    return { decision: CH_ALLOW, reason: '' };
  }
}

module.exports = {
  CH_ALLOW, CH_DENY, CH_REASON, CH_MAX_HANDLE_BYTES,
  defaultCaptureHandlePolicy, byteLen, hasControlChar, regSite, CaptureHandleGuard,
};
