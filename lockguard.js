'use strict';

// lockguard.js —— Web Locks API（navigator.locks.request）跨源锁名与资源占用裁决内核。
//
// 威胁模型：
//   1. 锁名是全局可见的协调原语，页面通过请求一组已知锁名并观察 granted/等待，可探测同源
//      其它标签是否打开了特定文档（如网银转账页、内部控制台），做状态指纹；
//   2. 恶意页面用 mode:'exclusive' 抢占公共锁名且长期不释放（hold 模式 + 死循环/await
//      永不 resolve），让正当功能（同步、数据库迁移）饥饿；
//   3. 一次 steal 其它持有者的锁，可打断正在进行的关键写事务；
//   4. 超长/海量锁名是脏数据，且可被用来做键碰撞；ifAvailable:true 被用来做隐蔽探测。
//
// 纯逻辑：对单次锁请求参数与持有状态做裁决与记账。

const LK_ALLOW = 'allow';
const LK_DENY = 'deny';

const LK_REASON = Object.freeze({
  BAD_CONTEXT: 'lk-bad-context',
  INSECURE_ORIGIN: 'lk-insecure-origin',
  BAD_NAME: 'lk-bad-name',
  NAME_TOO_LONG: 'lk-name-too-long',
  NAME_CONTROL_CHAR: 'lk-name-control-char',
  TOO_MANY_LOCKS: 'lk-too-many-locks',
  STEAL_NOT_ALLOWED: 'lk-steal-not-allowed',
  EXCLUSIVE_PROBE_DENIED: 'lk-exclusive-probe-denied',
  HOLD_FOREVER: 'lk-hold-forever',
  RATE_LIMIT: 'lk-rate-limit',
});

function defaultLockPolicy() {
  return {
    requireHttps: false,
    maxNameLength: 256,
    maxHeldLocksPerOrigin: 32,
    maxLockRequestsPerMinute: 200,
    allowSteal: false,
    blockExclusiveProbe: true, // ifAvailable + exclusive 的纯探测组合
    maxHoldMs: 30000,
    // 被保护的敏感锁名前缀：仅允许非独占/共享式短持。
    protectedNamePrefixes: ['payment-', 'transfer-', 'migration-', 'sync-'],
  };
}

function hasControlChar(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

class LockGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultLockPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.held = new Map(); // origin -> Set(name)
    this.requestTimes = new Map(); // origin -> [timestamps]
  }

  _isProtected(name) {
    for (const p of this.policy.protectedNamePrefixes) {
      if (name.indexOf(p) === 0) return true;
    }
    return false;
  }

  _rateLimited(origin) {
    const now = this.clock();
    const arr = this.requestTimes.get(origin) || [];
    const fresh = arr.filter((ts) => now - ts < 60000);
    if (fresh.length >= this.policy.maxLockRequestsPerMinute) {
      this.requestTimes.set(origin, fresh);
      return true;
    }
    fresh.push(now);
    this.requestTimes.set(origin, fresh);
    return false;
  }

  // decideRequest 裁决 navigator.locks.request(name, options)。
  // options: {mode:'shared'|'exclusive', steal, ifAvailable, holdMs, signalPersistent}
  decideRequest(ctx, name, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: LK_DENY, reason: LK_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: LK_DENY, reason: LK_REASON.INSECURE_ORIGIN };
    if (typeof name !== 'string' || name.length === 0) return { decision: LK_DENY, reason: LK_REASON.BAD_NAME };
    if (name.length > pol.maxNameLength) return { decision: LK_DENY, reason: LK_REASON.NAME_TOO_LONG };
    if (hasControlChar(name)) return { decision: LK_DENY, reason: LK_REASON.NAME_CONTROL_CHAR };

    const o = options && typeof options === 'object' ? options : {};
    const mode = o.mode === 'shared' ? 'shared' : 'exclusive';

    if (o.steal === true && !pol.allowSteal) return { decision: LK_DENY, reason: LK_REASON.STEAL_NOT_ALLOWED };
    if (this._rateLimited(ctx.origin)) return { decision: LK_DENY, reason: LK_REASON.RATE_LIMIT };

    // 对受保护锁名：拒绝独占抢占式探测（ifAvailable 立即返回失败常用于探测存在性）。
    if (pol.blockExclusiveProbe && this._isProtected(name) &&
        mode === 'exclusive' && o.ifAvailable === true) {
      return { decision: LK_DENY, reason: LK_REASON.EXCLUSIVE_PROBE_DENIED, name };
    }

    const holdMs = typeof o.holdMs === 'number' ? o.holdMs : 0;
    // signalPersistent/永不释放：holdMs 为 0 且声明持久，按饿死风险拦。
    if (holdMs > pol.maxHoldMs || (holdMs === 0 && o.holdForever === true)) {
      return { decision: LK_DENY, reason: LK_REASON.HOLD_FOREVER, holdMs };
    }

    const set = this.held.get(ctx.origin) || new Set();
    if (!set.has(name) && set.size >= pol.maxHeldLocksPerOrigin) {
      return { decision: LK_DENY, reason: LK_REASON.TOO_MANY_LOCKS };
    }
    set.add(name);
    this.held.set(ctx.origin, set);
    return { decision: LK_ALLOW, reason: '', mode };
  }

  release(ctx, name) {
    if (!ctx) return;
    const set = this.held.get(ctx.origin);
    if (set) set.delete(name);
  }

  heldCount(origin) {
    const set = this.held.get(origin);
    return set ? set.size : 0;
  }
}

module.exports = {
  LK_ALLOW, LK_DENY, LK_REASON,
  defaultLockPolicy, hasControlChar, LockGuard,
};
