'use strict';

// periodicbgsyncguard.js —— Periodic Background Sync / Background Fetch 后台联网裁决内核。
//
// 威胁模型：
//   1. serviceWorkerRegistration.periodicSync.register 允许网页在用户不打开页面时由
//      浏览器周期性唤醒 SW 联网，可做长期后台信标、上报历史浏览/本地数据、拉取追踪配置；
//   2. minInterval 被设得极小，唤醒频率逼近常驻；标签关闭后仍持续运行，无 UI 感知；
//   3. Background Fetch 可在后台发起大文件下载/上传，绕过前台下载提示与配额感知；
//   4. 非安全上下文或未经安装（PWA 安装态/standalone）的普通站点申请后台能力；
//   5. 标签/来源被拦截后仍保留已注册的周期任务，需要在撤销时 unregister。
//
// 纯逻辑：安装态/权限门、最小周期间隔、每来源任务数、后台传输体积与并发、撤销即失效。

const PB_DENY = 'deny';
const PB_ALLOW = 'allow';

const PB_REASON = Object.freeze({
  INSECURE_CONTEXT: 'pb-insecure-context',
  BAD_ORIGIN: 'pb-bad-origin',
  BLOCKED_ORIGIN: 'pb-blocked-origin',
  NOT_INSTALLED: 'pb-not-installed',
  PERMISSION_NOT_GRANTED: 'pb-permission-not-granted',
  INTERVAL_TOO_SMALL: 'pb-interval-too-small',
  TOO_MANY_TAGS: 'pb-too-many-tags',
  TAG_ALREADY_REGISTERED: 'pb-tag-already-registered',
  BG_FETCH_TOO_LARGE: 'pb-bg-fetch-too-large',
  TOO_MANY_BG_FETCH: 'pb-too-many-bg-fetch',
});

function defaultPeriodicBgPolicy() {
  return {
    requireSecureContext: true,
    requireInstalled: true, // 仅已安装 PWA 可申请周期后台同步
    permissionGranted: false,
    minPeriodicIntervalMs: 12 * 60 * 60000, // 最小 12 小时
    maxPeriodicTagsPerOrigin: 1,
    maxBackgroundFetchBytes: 50 * 1024 * 1024,
    maxConcurrentBackgroundFetch: 1,
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

class PeriodicBgSyncGuard {
  constructor(policy) {
    this.policy = policy || defaultPeriodicBgPolicy();
    this.tags = new Map(); // origin -> Set
    this.bgFetchCount = new Map();
  }

  _base(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { ok: false, reason: PB_REASON.BAD_ORIGIN };
    if (pol.requireSecureContext && ctx.isSecureContext !== true) {
      return { ok: false, reason: PB_REASON.INSECURE_CONTEXT };
    }
    const key = originKey(ctx.origin);
    if (!key) return { ok: false, reason: PB_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { ok: false, reason: PB_REASON.BLOCKED_ORIGIN };
    return { ok: true, key };
  }

  // decideRegisterPeriodic 裁决 periodicSync.register(tag,{minInterval})。
  decideRegisterPeriodic(ctx, tag, options) {
    const b = this._base(ctx);
    if (!b.ok) return { allowed: false, reason: b.reason };
    const pol = this.policy;
    if (pol.requireInstalled && ctx.isInstalled !== true) {
      return { allowed: false, reason: PB_REASON.NOT_INSTALLED };
    }
    if (!pol.permissionGranted) return { allowed: false, reason: PB_REASON.PERMISSION_NOT_GRANTED };
    const interval = options && typeof options.minInterval === 'number'
      ? options.minInterval : pol.minPeriodicIntervalMs;
    if (interval < pol.minPeriodicIntervalMs) {
      return { allowed: false, reason: PB_REASON.INTERVAL_TOO_SMALL };
    }
    let set = this.tags.get(b.key);
    if (!set) { set = new Set(); this.tags.set(b.key, set); }
    if (set.has(tag)) return { allowed: false, reason: PB_REASON.TAG_ALREADY_REGISTERED };
    if (set.size >= pol.maxPeriodicTagsPerOrigin) {
      return { allowed: false, reason: PB_REASON.TOO_MANY_TAGS };
    }
    set.add(tag);
    return { allowed: true, reason: '', effectiveIntervalMs: Math.max(interval, pol.minPeriodicIntervalMs) };
  }

  unregister(origin, tag) {
    const set = this.tags.get(originKey(origin));
    if (set) set.delete(tag);
  }

  revokeAll(origin) {
    this.tags.delete(originKey(origin));
  }

  // decideBackgroundFetch 裁决 backgroundFetch.fetch(id, requests, {downloadTotal})。
  decideBackgroundFetch(ctx, downloadTotalBytes) {
    const b = this._base(ctx);
    if (!b.ok) return { allowed: false, reason: b.reason };
    const pol = this.policy;
    if (pol.requireInstalled && ctx.isInstalled !== true) {
      return { allowed: false, reason: PB_REASON.NOT_INSTALLED };
    }
    if ((this.bgFetchCount.get(b.key) || 0) >= pol.maxConcurrentBackgroundFetch) {
      return { allowed: false, reason: PB_REASON.TOO_MANY_BG_FETCH };
    }
    if (typeof downloadTotalBytes === 'number' && downloadTotalBytes > pol.maxBackgroundFetchBytes) {
      return { allowed: false, reason: PB_REASON.BG_FETCH_TOO_LARGE, bytes: downloadTotalBytes };
    }
    this.bgFetchCount.set(b.key, (this.bgFetchCount.get(b.key) || 0) + 1);
    return { allowed: true, reason: '' };
  }

  noteBackgroundFetchDone(origin) {
    const key = originKey(origin);
    this.bgFetchCount.set(key, Math.max(0, (this.bgFetchCount.get(key) || 1) - 1));
  }

  periodicTagCount(origin) {
    const set = this.tags.get(originKey(origin));
    return set ? set.size : 0;
  }
}

module.exports = {
  PB_ALLOW, PB_DENY, PB_REASON,
  defaultPeriodicBgPolicy, originKey, PeriodicBgSyncGuard,
};
