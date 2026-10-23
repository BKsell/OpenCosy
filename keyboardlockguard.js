'use strict';

// keyboardlockguard.js —— navigator.keyboard.lock() 的捕获键白名单与手势门内核。
//
// 威胁模型：
//   Keyboard Lock 允许页面捕获通常被浏览器/系统保留的键：Esc、Alt+Tab、
//   Cmd/Win 键、F1-F12、浏览器快捷键等。全屏游戏有正当需求，但恶意页面可：
//     1. lock() 不传参数 = 请求捕获“所有可用键”，连 Esc 退出全屏都吞掉，制造
//        无法退出的钓鱼/勒索全屏（browser locker）；
//     2. 无手势、后台、iframe 里锁定系统键；
//     3. 捕获操作系统保留修饰键（Meta/Cmd、Alt+Tab）干扰任务切换；
//     4. 锁定后忽略 unlock，长时间不释放。
//
// 本模块裁决“这组 key code 是否允许锁、是否需要手势/全屏”，并要求显式列举
// 键名（拒绝空数组=全捕获的语义）。不直接调用 Keyboard API。

const KL_DENY = 'deny';
const KL_PROMPT = 'prompt';
const KL_ALLOW = 'allow';

const KL_REASON = Object.freeze({
  INSECURE_CONTEXT: 'kl-insecure-context',
  BAD_ORIGIN: 'kl-bad-origin',
  NO_GESTURE: 'kl-no-user-gesture',
  BACKGROUND: 'kl-background-tab',
  UNTRUSTED_FRAME: 'kl-untrusted-frame',
  REQUIRES_FULLSCREEN: 'kl-requires-fullscreen',
  EMPTY_LOCK_ALL: 'kl-empty-means-capture-all',
  FORBIDDEN_KEY: 'kl-forbidden-key',
  UNKNOWN_KEY: 'kl-unknown-key',
  TOO_MANY_KEYS: 'kl-too-many-keys',
  DUPLICATE_KEY: 'kl-duplicate-key',
  THROTTLED: 'kl-request-throttled',
  ORIGIN_BLOCKED: 'kl-origin-blocked',
});

// 即使页面请求也绝不放行的键：系统/浏览器逃生与切换键。
const FORBIDDEN_KEYS = Object.freeze(new Set([
  'Meta', 'MetaLeft', 'MetaRight', 'OS',
  'AltGraph', 'AltLeft', 'AltRight',
  'Tab',
  'Escape',
  'F1', 'F3', 'F5', 'F6', 'F7', // 帮助/查找/刷新/窗口切换等
  'Power', 'Sleep', 'Wake',
  'LaunchApp1', 'LaunchApp2', 'LaunchMail',
  'BrowserBack', 'BrowserForward', 'BrowserHome', 'BrowserRefresh', 'BrowserSearch',
  'PrintScreen', 'ContextMenu',
]));

// 已知可在显式请求 + 全屏 + 手势下放行的键（游戏/演示常用）。
const ALLOWABLE_KEYS = Object.freeze(new Set([
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
  'Space', 'Enter', 'ShiftLeft', 'ShiftRight', 'ControlLeft', 'ControlRight',
  'KeyW', 'KeyA', 'KeyS', 'KeyD', 'KeyQ', 'KeyE', 'KeyR', 'KeyF',
  'Digit1', 'Digit2', 'Digit3', 'Digit4', 'Digit5', 'Digit6',
  'F2', 'F4', 'F8', 'F9', 'F10', 'F11', 'F12',
  'Backspace', 'Delete',
]));

function defaultKeyboardLockPolicy() {
  return {
    requireSecureContext: true,
    requireUserGesture: true,
    denyBackground: true,
    allowIframes: false,
    requireFullscreen: true,
    maxKeys: 16,
    reRequestMinIntervalMs: 1000,
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

function normalizeKey(k) {
  if (typeof k !== 'string') return '';
  return k.trim();
}

class KeyboardLockGuard {
  constructor(policy) {
    this.policy = policy || defaultKeyboardLockPolicy();
    this.lastRequestAt = new Map();
  }

  // decideLock 裁决一次 keyboard.lock(...keys)。
  // keys 为页面传入的键名数组；空数组/缺省在规范里表示“捕获全部”，必须拒绝。
  decideLock(ctx, keys) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') {
      return { decision: KL_DENY, reason: KL_REASON.BAD_ORIGIN };
    }
    if (pol.requireSecureContext && !ctx.isSecureContext) {
      return { decision: KL_DENY, reason: KL_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { decision: KL_DENY, reason: KL_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: KL_DENY, reason: KL_REASON.ORIGIN_BLOCKED };
    if (!pol.allowIframes && ctx.isTopFrame === false) {
      return { decision: KL_DENY, reason: KL_REASON.UNTRUSTED_FRAME };
    }
    if (pol.denyBackground && ctx.isBackground === true) {
      return { decision: KL_DENY, reason: KL_REASON.BACKGROUND };
    }
    if (pol.requireFullscreen && ctx.isFullscreen !== true) {
      return { decision: KL_DENY, reason: KL_REASON.REQUIRES_FULLSCREEN };
    }
    const now = ctx.now || 0;
    const last = this.lastRequestAt.get(key) || 0;
    if (now - last < pol.reRequestMinIntervalMs) {
      return { decision: KL_PROMPT, reason: KL_REASON.THROTTLED };
    }

    const list = Array.isArray(keys) ? keys : [];
    if (list.length === 0) {
      return { decision: KL_DENY, reason: KL_REASON.EMPTY_LOCK_ALL };
    }
    if (list.length > pol.maxKeys) {
      return { decision: KL_DENY, reason: KL_REASON.TOO_MANY_KEYS };
    }
    const seen = new Set();
    for (const raw of list) {
      const k = normalizeKey(raw);
      if (k === '') return { decision: KL_DENY, reason: KL_REASON.UNKNOWN_KEY };
      if (FORBIDDEN_KEYS.has(k)) {
        return { decision: KL_DENY, reason: KL_REASON.FORBIDDEN_KEY, key: k };
      }
      if (!ALLOWABLE_KEYS.has(k)) {
        return { decision: KL_DENY, reason: KL_REASON.UNKNOWN_KEY, key: k };
      }
      if (seen.has(k)) {
        return { decision: KL_DENY, reason: KL_REASON.DUPLICATE_KEY, key: k };
      }
      seen.add(k);
    }

    if (pol.requireUserGesture && ctx.hasUserGesture !== true) {
      return { decision: KL_DENY, reason: KL_REASON.NO_GESTURE };
    }
    this.lastRequestAt.set(key, now);
    return { decision: KL_ALLOW, reason: '', keys: Array.from(seen) };
  }
}

module.exports = {
  KL_DENY, KL_PROMPT, KL_ALLOW, KL_REASON,
  FORBIDDEN_KEYS, ALLOWABLE_KEYS,
  defaultKeyboardLockPolicy, originKey, KeyboardLockGuard,
};
