'use strict';

// fullscreenphishguard.js —— Fullscreen API 滥用（钓鱼全屏/UI 伪装/焦点欺骗）裁决内核。
//
// 威胁模型：
//   1. 页面 requestFullscreen 后绘制与操作系统/浏览器一模一样的登录界面，
//      用户误以为在原生环境输入密码（fullscreen phishing）；
//   2. 无手势或失焦/后台进入全屏，配合 Pointer Lock 做点击劫持与强制交互；
//   3. 全屏 + Pointer Lock + 伪造浏览器边框，覆盖安全指示（锁形图标/域名）；
//   4. navigationUI:'hide' 要求隐藏浏览器 UI，降低用户对真实 URL 的感知；
//   5. 子框架（iframe）未经委派进入全屏；
//   6. 退出键被 Pointer Lock/键盘事件拦截吞掉。
//
// 纯逻辑：裁决进入全屏、锁定指针叠加、UI 隐藏与子框架委派。

const FP_DENY = 'deny';
const FP_ALLOW = 'allow';
const FP_PROMPT = 'prompt';

const FP_REASON = Object.freeze({
  INSECURE_CONTEXT: 'fp-insecure-context',
  BAD_ORIGIN: 'fp-bad-origin',
  BLOCKED_ORIGIN: 'fp-blocked-origin',
  NO_GESTURE: 'fp-requires-gesture',
  NOT_FOCUSED: 'fp-not-focused',
  BACKGROUND: 'fp-background',
  SUBFRAME_NOT_ALLOWED: 'fp-subframe-not-allowed',
  NAV_UI_HIDE_FORBIDDEN: 'fp-navigation-ui-hide-forbidden',
  POINTER_LOCK_WITH_FULLSCREEN: 'fp-pointer-lock-with-fullscreen',
  FULLSCREEN_THROTTLED: 'fp-fullscreen-throttled',
});

function defaultFullscreenPhishPolicy() {
  return {
    requireSecureContext: true,
    requireGesture: true,
    requireFocus: true,
    denyBackground: true,
    allowSubframe: false,
    allowHideNavigationUI: false,
    allowPointerLockCombo: false,
    enterMinIntervalMs: 2000,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.indexOf('/') >= 0 || rest.indexOf('?') >= 0) return '';
  return scheme + '://' + rest.toLowerCase();
}

class FullscreenPhishGuard {
  constructor(policy) {
    this.policy = policy || defaultFullscreenPhishPolicy();
    this.lastEnter = new Map();
  }

  // decideEnter 裁决 Element.requestFullscreen(options)。
  // ctx: {origin, isSecureContext, blocked, hasUserGesture, hasFocus, isBackground,
  //       isTopFrame, now, alsoPointerLock}
  decideEnter(ctx, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: FP_DENY, reason: FP_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { decision: FP_DENY, reason: FP_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: FP_DENY, reason: FP_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: FP_DENY, reason: FP_REASON.BLOCKED_ORIGIN };
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: FP_DENY, reason: FP_REASON.BACKGROUND };
    }
    if (pol.requireGesture && ctx.hasUserGesture !== true) {
      return { decision: FP_DENY, reason: FP_REASON.NO_GESTURE };
    }
    if (pol.requireFocus && ctx.hasFocus !== true) {
      return { decision: FP_DENY, reason: FP_REASON.NOT_FOCUSED };
    }
    if (ctx.isTopFrame === false && !pol.allowSubframe) {
      return { decision: FP_DENY, reason: FP_REASON.SUBFRAME_NOT_ALLOWED };
    }
    const now = ctx.now || 0;
    if (this.lastEnter.has(key) && now - this.lastEnter.get(key) < pol.enterMinIntervalMs) {
      return { decision: FP_DENY, reason: FP_REASON.FULLSCREEN_THROTTLED };
    }
    if (options && String(options.navigationUI).toLowerCase() === 'hide' && !pol.allowHideNavigationUI) {
      return { decision: FP_DENY, reason: FP_REASON.NAV_UI_HIDE_FORBIDDEN };
    }
    if (ctx.alsoPointerLock === true && !pol.allowPointerLockCombo) {
      return { decision: FP_DENY, reason: FP_REASON.POINTER_LOCK_WITH_FULLSCREEN };
    }
    this.lastEnter.set(key, now);
    return { decision: FP_ALLOW, reason: '' };
  }

  // mustShowExitNotice 返回进入全屏后是否必须展示持久"Esc 退出全屏 + 域名"提示。
  mustShowExitNotice() {
    return true;
  }
}

module.exports = {
  FP_ALLOW, FP_DENY, FP_PROMPT, FP_REASON,
  defaultFullscreenPhishPolicy, originKey, FullscreenPhishGuard,
};
