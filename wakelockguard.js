'use strict';

// wakelockguard.js —— Screen Wake Lock API（navigator.wakeLock.request('screen')）裁决内核。
//
// 威胁模型：
//   1. 页面持有 screen wake lock 让屏幕常亮，配合隐藏视频/定时器做长时间后台跟踪与
//      保活，阻止系统休眠断开它的网络连接；
//   2. 锁屏被阻止后，设备无人看管时屏幕持续点亮，旁人可看到/操作已登录会话（肩窥）；
//   3. 耗电与发热被滥用（恶意网页挖矿/压测前端）；
//   4. 无手势请求、切到后台/隐藏标签仍试图重新申请（visibilitychange 自动 re-request）；
//   5. 多标签/多实例叠加持有，延长最大常亮时间。
//
// 纯逻辑：申请门、可见性/后台、最长持有时间、自动重申请频控、累计时长上限。

const WL_DENY = 'deny';
const WL_ALLOW = 'allow';

const WL_REASON = Object.freeze({
  INSECURE_CONTEXT: 'wl-insecure-context',
  BAD_ORIGIN: 'wl-bad-origin',
  BLOCKED_ORIGIN: 'wl-blocked-origin',
  NO_GESTURE: 'wl-requires-gesture',
  HIDDEN_FORBIDDEN: 'wl-hidden-forbidden',
  WRONG_LOCK_TYPE: 'wl-wrong-lock-type',
  ALREADY_HELD: 'wl-already-held',
  HOLD_TOO_LONG: 'wl-hold-too-long',
  REACQUIRE_THROTTLED: 'wl-reacquire-throttled',
  CUMULATIVE_LIMIT: 'wl-cumulative-limit',
});

function defaultWakeLockPolicy() {
  return {
    requireSecureContext: true,
    requireGesture: true,
    denyWhenHidden: true,
    allowedType: 'screen',
    maxSingleHoldMs: 5 * 60000,
    maxCumulativeMsPerOrigin: 30 * 60000,
    reacquireMinIntervalMs: 3000,
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

class WakeLockGuard {
  constructor(policy) {
    this.policy = policy || defaultWakeLockPolicy();
    this.heldSince = new Map();
    this.lastAcquire = new Map();
    this.cumulative = new Map();
  }

  // decideRequest 裁决 wakeLock.request(type)。
  // ctx: {origin,isSecureContext,blocked,hasUserGesture,isHidden,isBackground,now}
  decideRequest(ctx, type) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: WL_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { allowed: false, reason: WL_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { allowed: false, reason: WL_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { allowed: false, reason: WL_REASON.BLOCKED_ORIGIN };
    if (type !== pol.allowedType) return { allowed: false, reason: WL_REASON.WRONG_LOCK_TYPE };
    if (pol.requireGesture && ctx.hasUserGesture !== true) {
      return { allowed: false, reason: WL_REASON.NO_GESTURE };
    }
    if (pol.denyWhenHidden && (ctx.isHidden === true || ctx.isBackground === true)) {
      return { allowed: false, reason: WL_REASON.HIDDEN_FORBIDDEN };
    }
    if (this.heldSince.has(key)) return { allowed: false, reason: WL_REASON.ALREADY_HELD };

    const now = ctx.now || 0;
    if (this.lastAcquire.has(key) && now - this.lastAcquire.get(key) < pol.reacquireMinIntervalMs) {
      return { allowed: false, reason: WL_REASON.REACQUIRE_THROTTLED };
    }
    if ((this.cumulative.get(key) || 0) >= pol.maxCumulativeMsPerOrigin) {
      return { allowed: false, reason: WL_REASON.CUMULATIVE_LIMIT };
    }
    this.heldSince.set(key, now);
    this.lastAcquire.set(key, now);
    return { allowed: true, reason: '', maxHoldMs: pol.maxSingleHoldMs };
  }

  // noteRelease 在锁释放/页面隐藏时结算累计时长。
  noteRelease(origin, now) {
    const key = originKey(origin);
    if (!this.heldSince.has(key)) return { released: false };
    const start = this.heldSince.get(key);
    const held = Math.max(0, (now || 0) - start);
    this.cumulative.set(key, (this.cumulative.get(key) || 0) + held);
    this.heldSince.delete(key);
    return { released: true, heldMs: held, cumulativeMs: this.cumulative.get(key) };
  }

  // tick 周期调用，超过单次最长持有时间要求释放。
  tick(origin, now) {
    const key = originKey(origin);
    if (!this.heldSince.has(key)) return { mustRelease: false };
    if ((now || 0) - this.heldSince.get(key) > this.policy.maxSingleHoldMs) {
      return { mustRelease: true, reason: WL_REASON.HOLD_TOO_LONG };
    }
    return { mustRelease: false };
  }

  isHeld(origin) {
    return this.heldSince.has(originKey(origin));
  }
}

module.exports = {
  WL_ALLOW, WL_DENY, WL_REASON,
  defaultWakeLockPolicy, originKey, WakeLockGuard,
};
