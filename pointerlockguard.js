'use strict';

// pointerlockguard.js —— Element.requestPointerLock 的手势门、透明/极小目标拒绝、
// 退出键保障与每源节流内核。
//
// 威胁模型：
//   Pointer Lock 把鼠标光标隐藏并把移动事件完全交给页面。恶意用途：
//     1. 点击劫持：透明/0 尺寸/被遮挡元素抢到指针锁，用户以为在点别处，实际被
//        劫持的指针流送进游戏/广告；
//     2. 无手势锁定：页面一加载或定时器里 requestPointerLock，用户根本没点；
//     3. 退出不了：锁后不监听 document.exitPointerLock、反复重入，吞掉 Esc；
//     4. 非全屏下长时间锁定做“光标绑架”，配合全屏伪造系统界面；
//     5. 短时间反复申请制造弹窗/状态抖动。
//
// 本模块裁决“是否允许进入指针锁、允许多久、是否要求全屏”，并管理“用户刚退出
// 后冷却期内不得立即重入”。不直接操作 DOM。

const PL_DENY = 'deny';
const PL_PROMPT = 'prompt';
const PL_ALLOW = 'allow';

const PL_REASON = Object.freeze({
  INSECURE_CONTEXT: 'pl-insecure-context',
  BAD_ORIGIN: 'pl-bad-origin',
  NO_GESTURE: 'pl-no-user-gesture',
  BACKGROUND: 'pl-background-tab',
  UNTRUSTED_FRAME: 'pl-untrusted-frame',
  TARGET_NOT_VISIBLE: 'pl-target-not-visible',
  TARGET_TOO_SMALL: 'pl-target-too-small',
  TARGET_OBSCURED: 'pl-target-obscured',
  COOLDOWN_AFTER_EXIT: 'pl-cooldown-after-user-exit',
  REQUIRES_FULLSCREEN: 'pl-requires-fullscreen',
  THROTTLED: 'pl-request-throttled',
  ORIGIN_BLOCKED: 'pl-origin-blocked',
});

function defaultPointerLockPolicy() {
  return {
    requireSecureContext: true,
    requireUserGesture: true,
    denyBackground: true,
    allowIframes: false,
    requireFullscreen: false,
    minTargetSizePx: 32,
    cooldownAfterExitMs: 2000,
    reRequestMinIntervalMs: 1000,
    maxAutoReentries: 1,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) return '';
  return scheme + '://' + rest.toLowerCase();
}

class PointerLockGuard {
  constructor(policy) {
    this.policy = policy || defaultPointerLockPolicy();
    this.lastRequestAt = new Map();
    this.exitCooldownUntil = new Map();
    this.autoReentries = new Map();
  }

  // target: { visible, width, height, opacity, obscuredByOverlay, isTopmostElement }
  // ctx: { origin, isSecureContext, hasUserGesture, isBackground, isTopFrame,
  //        isFullscreen, blocked, now }
  decideRequest(ctx, target) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') {
      return { decision: PL_DENY, reason: PL_REASON.BAD_ORIGIN };
    }
    if (pol.requireSecureContext && !ctx.isSecureContext) {
      return { decision: PL_DENY, reason: PL_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: PL_DENY, reason: PL_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: PL_DENY, reason: PL_REASON.ORIGIN_BLOCKED };
    if (!pol.allowIframes && ctx.isTopFrame === false) {
      return { decision: PL_DENY, reason: PL_REASON.UNTRUSTED_FRAME };
    }
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: PL_DENY, reason: PL_REASON.BACKGROUND };
    }

    const now = ctx.now || 0;
    // 用户刚主动退出：冷却期内拒绝（区分用户退出与程序自动重入）。
    if (now < (this.exitCooldownUntil.get(key) || 0)) {
      return { decision: PL_DENY, reason: PL_REASON.COOLDOWN_AFTER_EXIT };
    }
    if (pol.requireFullscreen && ctx.isFullscreen !== true) {
      return { decision: PL_DENY, reason: PL_REASON.REQUIRES_FULLSCREEN };
    }

    // 目标元素可见性/尺寸/遮挡。
    const t = target || {};
    if (t.visible === false || t.opacity === 0) {
      return { decision: PL_DENY, reason: PL_REASON.TARGET_NOT_VISIBLE };
    }
    const min = pol.minTargetSizePx;
    if (typeof t.width === 'number' && typeof t.height === 'number' &&
      (t.width < min || t.height < min)) {
      return { decision: PL_DENY, reason: PL_REASON.TARGET_TOO_SMALL };
    }
    if (t.obscuredByOverlay === true || t.isTopmostElement === false) {
      return { decision: PL_DENY, reason: PL_REASON.TARGET_OBSCURED };
    }

    const isGesture = ctx.hasUserGesture === true;
    if (pol.requireUserGesture && !isGesture) {
      // 无手势：仅允许极少量自动重入（指针锁意外丢失的恢复），且要节流。
      const re = this.autoReentries.get(key) || 0;
      if (re >= pol.maxAutoReentries) {
        return { decision: PL_DENY, reason: PL_REASON.NO_GESTURE };
      }
      const last = this.lastRequestAt.get(key) || 0;
      if (now - last < pol.reRequestMinIntervalMs) {
        return { decision: PL_PROMPT, reason: PL_REASON.THROTTLED };
      }
      this.autoReentries.set(key, re + 1);
      this.lastRequestAt.set(key, now);
      return { decision: PL_ALLOW, reason: '', autoReentry: true };
    }

    const last = this.lastRequestAt.get(key) || 0;
    if (now - last < pol.reRequestMinIntervalMs) {
      return { decision: PL_PROMPT, reason: PL_REASON.THROTTLED };
    }
    this.lastRequestAt.set(key, now);
    this.autoReentries.set(key, 0);
    return { decision: PL_ALLOW, reason: '' };
  }

  // noteUserExit 在用户按 Esc 等主动退出时调用，开启冷却。
  noteUserExit(origin, now) {
    const key = originKey(origin);
    this.exitCooldownUntil.set(key, now + this.policy.cooldownAfterExitMs);
    this.autoReentries.set(key, 0);
  }

  // programmaticExit 是页面自身 exitPointerLock，不施加冷却。
  programmaticExit(origin) {
    this.autoReentries.set(originKey(origin), 0);
  }
}

module.exports = {
  PL_DENY, PL_PROMPT, PL_ALLOW, PL_REASON,
  defaultPointerLockPolicy, originKey, PointerLockGuard,
};
