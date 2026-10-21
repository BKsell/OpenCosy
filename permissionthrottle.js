'use strict';

// permissionthrottle.js —— 站点敏感权限请求的节流、退避与持久决策内核。
//
// 威胁模型：
//   现代浏览器把 geolocation / camera / microphone / notifications /
//   clipboard / sensors / midi 等能力收敛到“用户授权”。但授权提示本身可被
//   滥用成攻击面：
//     1. 权限弹窗洪流：页面在循环 / 多个 iframe 里反复 requestPermission，
//        把原生授权框刷成噪声，用户在疲劳下点“允许”，或浏览器卡死；
//     2. 无用户手势触发：页面一加载（甚至后台标签）就请求摄像头/定位，
//        这与用户真实意图无关，风险显著更高；
//     3. 被拒后立刻重试，不给用户反应时间，用视觉遮挡诱导再次点击；
//     4. 子框架用更宽松的嵌入上下文套权限，或同一页面用不同 permission 名
//        分别骚扰，绕过单键计数。
//
// 本模块是纯逻辑裁决器（不调浏览器 API、不触 DOM）：主进程在真正弹原生授权
// 框之前调用 decide()，根据时间窗突发量、手势、退避状态、持久决策给出
// allow / block / suppress / prompt。所有时间由注入的 now() 提供，便于穷举测试。

const DECIDE = Object.freeze({
  ALLOW: 'allow',       // 命中持久允许，直接放行不弹窗
  BLOCK: 'block',       // 命中持久拒绝 / 策略硬拒，不弹窗
  SUPPRESS: 'suppress', // 节流/退避期，本次静默丢弃，不弹窗
  PROMPT: 'prompt',     // 允许弹原生授权框
});

// 已知敏感权限名（未知名称默认按最严格处理，不因拼写陌生而放行）。
const KNOWN_PERMISSIONS = Object.freeze([
  'geolocation', 'camera', 'microphone', 'notifications',
  'clipboard-read', 'clipboard-write', 'midi', 'sensors',
  'persistent-storage', 'pointer-lock', 'fullscreen',
]);

const DEFAULT_POLICY = Object.freeze({
  windowMs: 60000,          // 突发统计窗口
  promptBurstLimit: 2,      // 窗口内允许弹窗的次数（无手势时更严，见下）
  promptBurstLimitGesture: 3,
  denyBackoffBaseMs: 2000,  // 被拒/忽略后的指数退避基数
  denyBackoffMaxMs: 300000, // 退避封顶 5 分钟
  maxDenyLevel: 6,
  grantTtlMs: 12 * 3600 * 1000,  // 持久允许有效期
  blockTtlMs: 24 * 3600 * 1000,  // 持久拒绝有效期
  requireGesture: ['camera', 'microphone', 'geolocation', 'midi', 'notifications'],
  embeddedExtraStrict: true,     // iframe 内嵌请求收紧
});

class PermissionThrottle {
  constructor(policy, nowFn) {
    this.policy = Object.assign({}, DEFAULT_POLICY, policy || {});
    this.now = typeof nowFn === 'function' ? nowFn : () => Date.now();
    // key -> { stamps:number[], denies:number, lastDenyAt:number }
    this.buckets = new Map();
    // key -> { decision:'allow'|'block', until:number }
    this.sticky = new Map();
  }

  key(origin, permission, embedded) {
    return origin + '|' + permission + '|' + (embedded ? '1' : '0');
  }

  _bucket(key) {
    let b = this.buckets.get(key);
    if (!b) {
      b = { stamps: [], denies: 0, lastDenyAt: 0 };
      this.buckets.set(key, b);
    }
    return b;
  }

  // 裁掉时间窗口外的历史弹窗时间戳。
  _prune(b, now) {
    const cutoff = now - this.policy.windowMs;
    while (b.stamps.length > 0 && b.stamps[0] <= cutoff) {
      b.stamps.shift();
    }
  }

  _backoffMs(denies) {
    const level = Math.min(denies, this.policy.maxDenyLevel);
    const ms = this.policy.denyBackoffBaseMs * Math.pow(2, level);
    return Math.min(ms, this.policy.denyBackoffMaxMs);
  }

  // decide 裁决一次权限请求。
  // req: { origin, permission, hasGesture, embedded }
  decide(req) {
    const p = this.policy;
    const origin = req && typeof req.origin === 'string' ? req.origin : '';
    const permission = req && typeof req.permission === 'string' ? req.permission : '';
    if (origin === '' || permission === '') {
      return { decision: DECIDE.BLOCK, reason: 'bad-request' };
    }
    const embedded = !!req.embedded;
    const hasGesture = !!req.hasGesture;
    const key = this.key(origin, permission, embedded);
    const now = this.now();

    // 1) 持久决策优先（未过期直接给结论，不弹窗）。
    const sticky = this.sticky.get(key);
    if (sticky && sticky.until > now) {
      return {
        decision: sticky.decision === 'allow' ? DECIDE.ALLOW : DECIDE.BLOCK,
        reason: 'sticky-' + sticky.decision,
      };
    } else if (sticky) {
      this.sticky.delete(key);
    }

    const b = this._bucket(key);
    this._prune(b, now);

    // 未知权限名：默认不弹窗（最保守）。
    if (!KNOWN_PERMISSIONS.includes(permission)) {
      return { decision: DECIDE.BLOCK, reason: 'unknown-permission' };
    }

    // 2) 退避期：最近被拒/忽略，静默丢弃。
    if (b.denies > 0 && b.lastDenyAt > 0) {
      const wait = this._backoffMs(b.denies);
      if (now - b.lastDenyAt < wait) {
        return { decision: DECIDE.SUPPRESS, reason: 'deny-backoff', retryAfterMs: wait - (now - b.lastDenyAt) };
      }
    }

    // 3) 高敏权限无手势：不弹窗（防止后台/加载即请求）。
    if (!hasGesture && p.requireGesture.includes(permission)) {
      b.denies++;
      b.lastDenyAt = now;
      return { decision: DECIDE.SUPPRESS, reason: 'requires-gesture' };
    }

    // 4) 突发量限制。嵌入上下文在无手势时用更严的阈值。
    let limit = hasGesture ? p.promptBurstLimitGesture : p.promptBurstLimit;
    if (embedded && p.embeddedExtraStrict && !hasGesture) {
      limit = Math.max(1, limit - 1);
    }
    if (b.stamps.length >= limit) {
      return { decision: DECIDE.SUPPRESS, reason: 'burst-limit' };
    }

    // 5) 放行弹窗并记录这次提示。
    b.stamps.push(now);
    return { decision: DECIDE.PROMPT, reason: '' };
  }

  // recordResult 由调用方在用户对原生框做出选择后回调。
  // result: 'allow' | 'block' | 'dismiss'（忽略/关闭）。
  recordResult(req, result) {
    const embedded = !!(req && req.embedded);
    const key = this.key(req.origin, req.permission, embedded);
    const now = this.now();
    const b = this._bucket(key);
    if (result === 'allow') {
      b.denies = 0;
      this.sticky.set(key, { decision: 'allow', until: now + this.policy.grantTtlMs });
      return;
    }
    // block / dismiss 都计入退避；block 额外持久化。
    b.denies = Math.min(b.denies + 1, this.policy.maxDenyLevel + 4);
    b.lastDenyAt = now;
    if (result === 'block') {
      this.sticky.set(key, { decision: 'block', until: now + this.policy.blockTtlMs });
    }
  }

  // resetSticky 供设置页“清除站点权限”调用，返回是否清除过。
  resetSticky(origin, permission) {
    let removed = false;
    for (const k of Array.from(this.sticky.keys())) {
      const [o, perm] = k.split('|');
      if (o === origin && (permission == null || perm === permission)) {
        this.sticky.delete(k);
        removed = true;
      }
    }
    return removed;
  }

  // snapshot 便于主进程持久化节流状态（只序列化必要字段）。
  snapshot() {
    const now = this.now();
    const buckets = {};
    for (const [k, b] of this.buckets) {
      this._prune(b, now);
      if (b.stamps.length || b.denies) {
        buckets[k] = { stamps: b.stamps.slice(), denies: b.denies, lastDenyAt: b.lastDenyAt };
      }
    }
    const sticky = {};
    for (const [k, s] of this.sticky) {
      if (s.until > now) sticky[k] = { decision: s.decision, until: s.until };
    }
    return { at: now, buckets, sticky };
  }

  // restore 从持久化数据恢复（对非法输入健壮，不抛异常）。
  restore(data) {
    if (!data || typeof data !== 'object') return false;
    this.buckets.clear();
    this.sticky.clear();
    if (data.buckets && typeof data.buckets === 'object') {
      for (const k of Object.keys(data.buckets)) {
        const src = data.buckets[k];
        if (!src || !Array.isArray(src.stamps)) continue;
        this.buckets.set(k, {
          stamps: src.stamps.filter(n => Number.isFinite(n)).slice(-50),
          denies: Number.isFinite(src.denies) ? src.denies : 0,
          lastDenyAt: Number.isFinite(src.lastDenyAt) ? src.lastDenyAt : 0,
        });
      }
    }
    if (data.sticky && typeof data.sticky === 'object') {
      for (const k of Object.keys(data.sticky)) {
        const src = data.sticky[k];
        if (src && (src.decision === 'allow' || src.decision === 'block') && Number.isFinite(src.until)) {
          this.sticky.set(k, { decision: src.decision, until: src.until });
        }
      }
    }
    return true;
  }
}

module.exports = {
  DECIDE,
  KNOWN_PERMISSIONS,
  DEFAULT_POLICY,
  PermissionThrottle,
};
