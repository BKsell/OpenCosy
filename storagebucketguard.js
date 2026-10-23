'use strict';

// storagebucketguard.js —— Storage Buckets API（navigator.storageBuckets.open）多桶配额与持久化裁决内核。
//
// 威胁模型：
//   1. Storage Buckets 允许站点创建大量命名桶（indexedDB/cacheStorage 各自独立），配合
//      persist() 可把追踪数据持久化、分散存放以规避"按源清理"与单点配额统计；
//   2. 桶名脏数据/海量桶做键碰撞与配额耗尽（挤掉同源正当存储）；
//   3. requested 配额虚报超大值；expires 设成超长把数据钉死；
//   4. 三方上下文借桶做跨站持久追踪；非安全上下文；
//   5. 删除/枚举其它桶的越权（名字空间未按调用方隔离时）。
//
// 纯逻辑。

const SB_ALLOW = 'allow';
const SB_DENY = 'deny';

const SB_REASON = Object.freeze({
  BAD_CONTEXT: 'sb-bad-context',
  INSECURE_ORIGIN: 'sb-insecure-origin',
  THIRD_PARTY: 'sb-third-party',
  BAD_NAME: 'sb-bad-name',
  NAME_TOO_LONG: 'sb-name-too-long',
  NAME_CONTROL_CHAR: 'sb-name-control-char',
  TOO_MANY_BUCKETS: 'sb-too-many-buckets',
  QUOTA_TOO_LARGE: 'sb-quota-too-large',
  PERSIST_DISABLED: 'sb-persist-disabled',
  EXPIRES_TOO_FAR: 'sb-expires-too-far',
  QUOTA_EXCEEDED: 'sb-quota-exceeded',
});

const SB_MAX_NAME_BYTES = 64;

function defaultStorageBucketPolicy() {
  return {
    requireHttps: true,
    blockThirdParty: true,
    maxNameBytes: SB_MAX_NAME_BYTES,
    maxBucketsPerOrigin: 16,
    maxRequestedQuotaBytes: 256 * 1024 * 1024,
    totalQuotaPerOrigin: 512 * 1024 * 1024,
    allowPersist: false,
    maxExpiresMsFromNow: 30 * 24 * 3600 * 1000,
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

class StorageBucketGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultStorageBucketPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.buckets = new Map(); // origin -> Map(name -> quota)
  }

  // decideOpen 裁决 storageBuckets.open(name, options)。
  // options: {quota:{}, persisted, expires}
  decideOpen(ctx, name, options) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: SB_DENY, reason: SB_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: SB_DENY, reason: SB_REASON.INSECURE_ORIGIN };
    if (pol.blockThirdParty && ctx.isTopFrame === false) return { decision: SB_DENY, reason: SB_REASON.THIRD_PARTY };

    if (typeof name !== 'string' || name.length === 0) return { decision: SB_DENY, reason: SB_REASON.BAD_NAME };
    if (byteLen(name) > pol.maxNameBytes) return { decision: SB_DENY, reason: SB_REASON.NAME_TOO_LONG };
    if (hasControlChar(name)) return { decision: SB_DENY, reason: SB_REASON.NAME_CONTROL_CHAR };

    const map = this.buckets.get(ctx.origin) || new Map();
    const opt = options && typeof options === 'object' ? options : {};

    const want = typeof opt.quota === 'number' ? opt.quota : 0;
    if (want > pol.maxRequestedQuotaBytes) return { decision: SB_DENY, reason: SB_REASON.QUOTA_TOO_LARGE, quota: want };
    if (opt.persisted === true && !pol.allowPersist) return { decision: SB_DENY, reason: SB_REASON.PERSIST_DISABLED };
    if (typeof opt.expires === 'number' && opt.expires - this.clock() > pol.maxExpiresMsFromNow) {
      return { decision: SB_DENY, reason: SB_REASON.EXPIRES_TOO_FAR };
    }

    if (!map.has(name) && map.size >= pol.maxBucketsPerOrigin) {
      return { decision: SB_DENY, reason: SB_REASON.TOO_MANY_BUCKETS };
    }
    let used = 0;
    for (const v of map.values()) used += v;
    const other = map.has(name) ? used - map.get(name) : used;
    if (other + want > pol.totalQuotaPerOrigin) return { decision: SB_DENY, reason: SB_REASON.QUOTA_EXCEEDED, used: other, want };

    map.set(name, want);
    this.buckets.set(ctx.origin, map);
    return { decision: SB_ALLOW, reason: '' };
  }

  bucketCount(origin) {
    const map = this.buckets.get(origin);
    return map ? map.size : 0;
  }
}

module.exports = {
  SB_ALLOW, SB_DENY, SB_REASON, SB_MAX_NAME_BYTES,
  defaultStorageBucketPolicy, byteLen, StorageBucketGuard,
};
