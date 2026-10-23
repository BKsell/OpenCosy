'use strict';

// sharedstorageguard.js —— Shared Storage API（window.sharedStorage）跨站隐私存储裁决内核。
//
// 威胁模型：
//   1. sharedStorage 允许跨站写入键值并在 worklet 里以"输出不回传页面"的名义做跨站决策，
//      是 Protected Audience/聚合归因时代的新型跨站追踪通道；
//   2. 第三方上下文（iframe/嵌入资源）写 sharedStorage 即可在不同发布者站点间持久化 ID；
//   3. key 用超长串/控制字符做碰撞探测，value 体积被放大占用配额；
//   4. append（累加）被用来做跨站计数/信标，run/selectURL 在 worklet 里做隐蔽分支；
//   5. 每页写操作/总写入字节无上限会导致配额耗尽与高频写盘。
//
// 纯逻辑。

const SS_ALLOW = 'allow';
const SS_DENY = 'deny';

const SS_REASON = Object.freeze({
  BAD_CONTEXT: 'ss-bad-context',
  INSECURE_ORIGIN: 'ss-insecure-origin',
  THIRD_PARTY_CONTEXT: 'ss-third-party-context',
  API_DISABLED: 'ss-api-disabled',
  BAD_KEY: 'ss-bad-key',
  KEY_TOO_LONG: 'ss-key-too-long',
  KEY_CONTROL_CHAR: 'ss-key-control-char',
  VALUE_TOO_LARGE: 'ss-value-too-large',
  APPEND_NOT_ALLOWED: 'ss-append-not-allowed',
  WORKLET_NOT_ALLOWED: 'ss-worklet-not-allowed',
  SELECT_URL_NOT_ALLOWED: 'ss-select-url-not-allowed',
  TOO_MANY_OPTIONS: 'ss-too-many-options',
  RATE_LIMIT: 'ss-rate-limit',
});

function defaultSharedStoragePolicy() {
  return {
    requireHttps: true,
    allowInThirdPartyContext: false,
    allowSet: true,
    allowAppend: false,
    allowDelete: true,
    allowRun: false,
    allowSelectURL: false,
    maxKeyLength: 128,
    maxValueBytes: 1024,
    maxSelectUrlOptions: 8,
    maxWritesPerOrigin: 64,
    maxWriteBytesPerOrigin: 32 * 1024,
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

class SharedStorageGuard {
  constructor(policy) {
    this.policy = policy || defaultSharedStoragePolicy();
    this.writeCount = new Map();
    this.writeBytes = new Map();
  }

  _gate(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return SS_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return SS_REASON.INSECURE_ORIGIN;
    if (!pol.allowInThirdPartyContext && ctx.isTopFrame === false) return SS_REASON.THIRD_PARTY_CONTEXT;
    return '';
  }

  _validateKey(key) {
    if (typeof key !== 'string' || key.length === 0) return SS_REASON.BAD_KEY;
    if (key.length > this.policy.maxKeyLength) return SS_REASON.KEY_TOO_LONG;
    if (hasControlChar(key)) return SS_REASON.KEY_CONTROL_CHAR;
    return '';
  }

  _rateLimited(origin, bytes) {
    const n = this.writeCount.get(origin) || 0;
    const b = this.writeBytes.get(origin) || 0;
    if (n >= this.policy.maxWritesPerOrigin || b + bytes > this.policy.maxWriteBytesPerOrigin) {
      return true;
    }
    this.writeCount.set(origin, n + 1);
    this.writeBytes.set(origin, b + bytes);
    return false;
  }

  // decide 裁决一次写操作。op: set/append/delete/run/selectURL。
  decide(ctx, op, key, value, options) {
    const bad = this._gate(ctx);
    if (bad) return { decision: SS_DENY, reason: bad };
    const pol = this.policy;

    if (op === 'run') {
      if (!pol.allowRun) return { decision: SS_DENY, reason: SS_REASON.WORKLET_NOT_ALLOWED };
      return { decision: SS_ALLOW, reason: '' };
    }
    if (op === 'selectURL') {
      if (!pol.allowSelectURL) return { decision: SS_DENY, reason: SS_REASON.SELECT_URL_NOT_ALLOWED };
      const opts = options && Array.isArray(options.urls) ? options.urls : [];
      if (opts.length > pol.maxSelectUrlOptions) return { decision: SS_DENY, reason: SS_REASON.TOO_MANY_OPTIONS, count: opts.length };
      return { decision: SS_ALLOW, reason: '' };
    }

    const keyErr = this._validateKey(key);
    if (keyErr) return { decision: SS_DENY, reason: keyErr };

    if (op === 'delete') {
      if (!pol.allowDelete) return { decision: SS_DENY, reason: SS_REASON.API_DISABLED };
      return { decision: SS_ALLOW, reason: '' };
    }
    if (op === 'append') {
      if (!pol.allowAppend) return { decision: SS_DENY, reason: SS_REASON.APPEND_NOT_ALLOWED };
    } else if (op !== 'set') {
      return { decision: SS_DENY, reason: SS_REASON.API_DISABLED };
    } else if (!pol.allowSet) {
      return { decision: SS_DENY, reason: SS_REASON.API_DISABLED };
    }

    const bytes = byteLen(typeof value === 'string' ? value : '');
    if (bytes > pol.maxValueBytes) return { decision: SS_DENY, reason: SS_REASON.VALUE_TOO_LARGE, bytes };
    if (this._rateLimited(ctx.origin, bytes)) return { decision: SS_DENY, reason: SS_REASON.RATE_LIMIT };
    return { decision: SS_ALLOW, reason: '', bytes };
  }

  resetForOrigin(origin) {
    this.writeCount.delete(origin);
    this.writeBytes.delete(origin);
  }
}

module.exports = {
  SS_ALLOW, SS_DENY, SS_REASON,
  defaultSharedStoragePolicy, byteLen, hasControlChar, SharedStorageGuard,
};
