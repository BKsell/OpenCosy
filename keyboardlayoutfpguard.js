'use strict';

// keyboardlayoutfpguard.js —— 键盘布局指纹（KeyboardEvent.code/key、KeyboardLayoutMap）裁决内核。
//
// 威胁模型：
//   1. 不同键盘布局（AZERTY/QWERTZ/德文/日文/中文输入法）下，同一物理按键的
//      event.key / event.code 组合不同；遍历按键即可推断布局与国籍，是稳定指纹；
//   2. navigator.keyboard.getLayoutMap() 直接返回"物理键→字符"映射，无需真实击键
//      就能读出布局（指纹更强，且可推断外籍/少数语种用户）；
//   3. getLayoutMap 还能配合 lock() 捕获特殊按键；
//   4. 页面监听 keydown 收集非交互键（Shift/Ctrl 组合、死键）做生物行为指纹；
//   5. 高频合成/真实事件采样建立击键节奏（keystroke dynamics）画像。
//
// 纯逻辑：getLayoutMap 门、布局探测预算、按键事件采样频控、敏感修饰键统计脱敏。

const KL_DENY = 'deny';
const KL_ALLOW = 'allow';

const KL_REASON = Object.freeze({
  INSECURE_CONTEXT: 'kl-insecure-context',
  BAD_ORIGIN: 'kl-bad-origin',
  BLOCKED_ORIGIN: 'kl-blocked-origin',
  LAYOUTMAP_FORBIDDEN: 'kl-layoutmap-forbidden',
  LAYOUTMAP_NO_GESTURE: 'kl-layoutmap-no-gesture',
  EVENT_SAMPLE_THROTTLED: 'kl-event-sample-throttled',
  PROBE_BUDGET_EXCEEDED: 'kl-probe-budget-exceeded',
});

function defaultKeyboardLayoutPolicy() {
  return {
    requireSecureContext: true,
    // 默认禁止页面直接读布局映射；白名单来源可放开。
    allowGetLayoutMap: false,
    layoutMapRequireGesture: true,
    // 单位时间允许用于"指纹采样"的按键事件数（正常输入不受此限，仅对疑似探测脚本限流）。
    maxKeyEventsPerWindow: 300,
    windowMs: 1000,
    // 每个 origin 最多探测的不同物理键数量。
    maxDistinctCodesPerOrigin: 64,
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

// genericLayoutValue 对布局映射值做泛化：只返回是否为可打印单字符，不返回真实字符。
function genericLayoutValue(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  return value.length === 1 ? 'x' : 'dead';
}

class KeyboardLayoutFpGuard {
  constructor(policy) {
    this.policy = policy || defaultKeyboardLayoutPolicy();
    this.events = new Map();
    this.codes = new Map();
  }

  // decideGetLayoutMap 裁决 navigator.keyboard.getLayoutMap()。
  decideGetLayoutMap(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: KL_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: KL_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: KL_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: KL_REASON.BLOCKED_ORIGIN };
    if (!pol.allowGetLayoutMap) return { allowed: false, reason: KL_REASON.LAYOUTMAP_FORBIDDEN };
    if (pol.layoutMapRequireGesture && ctx.hasUserGesture !== true) {
      return { allowed: false, reason: KL_REASON.LAYOUTMAP_NO_GESTURE };
    }
    return { allowed: true, reason: '', generic: genericLayoutValue };
  }

  // generalizeMap 供上层把真实布局映射替换为泛化版。
  generalizeMap(realMap) {
    const out = {};
    const entries = realMap instanceof Map ? Array.from(realMap.entries()) : Object.entries(realMap || {});
    for (const [k, v] of entries) out[k] = genericLayoutValue(v);
    return out;
  }

  // noteKeyEvent 记录一次 keydown，返回是否允许用于指纹采样。
  // code 为 event.code（物理键），用于去重预算。
  noteKeyEvent(ctx, code) {
    const pol = this.policy;
    const key = originKey(ctx && ctx.origin);
    if (!key) return { allowed: false, reason: KL_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: KL_REASON.BLOCKED_ORIGIN };
    const now = ctx.now || 0;
    let evs = this.events.get(key) || [];
    evs = evs.filter((t) => now - t < pol.windowMs);
    if (evs.length >= pol.maxKeyEventsPerWindow) {
      this.events.set(key, evs);
      return { allowed: false, reason: KL_REASON.EVENT_SAMPLE_THROTTLED };
    }
    evs.push(now);
    this.events.set(key, evs);

    if (typeof code === 'string' && code !== '') {
      let set = this.codes.get(key);
      if (!set) { set = new Set(); this.codes.set(key, set); }
      if (!set.has(code)) {
        if (set.size >= pol.maxDistinctCodesPerOrigin) {
          return { allowed: false, reason: KL_REASON.PROBE_BUDGET_EXCEEDED };
        }
        set.add(code);
      }
    }
    return { allowed: true, reason: '' };
  }

  distinctCodeCount(origin) {
    const set = this.codes.get(originKey(origin));
    return set ? set.size : 0;
  }
}

module.exports = {
  KL_ALLOW, KL_DENY, KL_REASON,
  defaultKeyboardLayoutPolicy, originKey, genericLayoutValue, KeyboardLayoutFpGuard,
};
