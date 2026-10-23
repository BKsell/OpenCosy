'use strict';

// beaconguard.js —— navigator.sendBeacon / fetch keepalive / img-ping 出向信标裁决内核。
//
// 威胁模型：
//   1. sendBeacon 专门用于 unload/pagehide 时把数据静默发给第三方，用户不可见、
//      无法被页面内取消，是分析与数据外泄（剪贴板、表单、指纹）的常用通道；
//   2. 第三方信标主机收集跨站行为画像；信标 URL 里塞查询参数带出敏感数据；
//   3. keepalive fetch 与大量 img/ping 在卸载阶段洪水发送，或向非 https 端点明文外泄；
//   4. Content-Type 被设成 application/x-www-form-urlencoded 携带大块结构化隐私数据；
//   5. blob/beacon 载荷体积被放大。
//
// 本模块做主机白名单/黑名单、scheme、体积、卸载阶段与跨子域裁决。纯逻辑。

const BC_DENY = 'deny';
const BC_ALLOW = 'allow';
const BC_STRIP = 'strip'; // 允许发送但要求去掉查询串/降体积

const BC_REASON = Object.freeze({
  BAD_ORIGIN: 'bc-bad-origin',
  BLOCKED_ORIGIN: 'bc-blocked-origin',
  INSECURE_TARGET: 'bc-insecure-target',
  BAD_SCHEME: 'bc-bad-scheme',
  THIRD_PARTY_NOT_ALLOWED: 'bc-third-party-not-allowed',
  HOST_BLOCKED: 'bc-host-blocked',
  PAYLOAD_TOO_LARGE: 'bc-payload-too-large',
  UNLOAD_FLOOD: 'bc-unload-flood',
  CROSS_ORIGIN_STRIP_QUERY: 'bc-cross-origin-strip-query',
});

function defaultBeaconPolicy() {
  return {
    requireHttpsTarget: true,
    allowThirdParty: false,
    allowedHosts: [], // 第三方主机白名单（allowThirdParty=false 时仍可用此清单）
    blockedHostSuffixes: [],
    maxBeaconBytes: 64 * 1024,
    maxUnloadBeacons: 2,
    stripQueryCrossOrigin: true,
  };
}

function originHost(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = origin.slice(idx + 3);
  for (const ch of ['/', '?', '#', ':']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  return rest.toLowerCase();
}

// targetSchemeHost 解析目标 URL 的 scheme 与 host（纯字符）。
function targetSchemeHost(url) {
  if (typeof url !== 'string') return { scheme: '', host: '', pathQuery: '' };
  const colon = url.indexOf(':');
  if (colon <= 0) return { scheme: '', host: '', pathQuery: '' };
  const scheme = url.slice(0, colon).toLowerCase();
  let rest = url.slice(colon + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  let host = rest;
  let pq = '';
  const slash = rest.indexOf('/');
  if (slash >= 0) { host = rest.slice(0, slash); pq = rest.slice(slash); } else { pq = ''; }
  const q = host.indexOf('?');
  if (q >= 0) { pq = host.slice(q) + pq; host = host.slice(0, q); }
  if (host.indexOf('@') >= 0) host = host.slice(host.lastIndexOf('@') + 1);
  if (host.indexOf('[') === 0) {
    const rb = host.indexOf(']');
    if (rb > 0) host = host.slice(1, rb);
  } else {
    const pc = host.lastIndexOf(':');
    if (pc > 0) host = host.slice(0, pc);
  }
  return { scheme, host: host.toLowerCase(), pathQuery: pq };
}

function sameRegistrable(hostA, hostB) {
  if (!hostA || !hostB) return false;
  return hostA === hostB || hostA.endsWith('.' + hostB) || hostB.endsWith('.' + hostA);
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

class BeaconGuard {
  constructor(policy) {
    this.policy = policy || defaultBeaconPolicy();
    this.unloadCounts = new Map();
  }

  // decideBeacon 裁决一次出向信标。
  // ctx: {origin, blocked, isUnloading}
  decideBeacon(ctx, targetUrl, payload) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { decision: BC_DENY, reason: BC_REASON.BAD_ORIGIN };
    const srcHost = originHost(ctx.origin);
    if (!srcHost) return { decision: BC_DENY, reason: BC_REASON.BAD_ORIGIN };
    if (ctx.blocked === true) return { decision: BC_DENY, reason: BC_REASON.BLOCKED_ORIGIN };

    const t = targetSchemeHost(targetUrl);
    if (t.scheme !== 'https' && t.scheme !== 'http') {
      return { decision: BC_DENY, reason: BC_REASON.BAD_SCHEME };
    }
    if (pol.requireHttpsTarget && t.scheme !== 'https') {
      return { decision: BC_DENY, reason: BC_REASON.INSECURE_TARGET };
    }
    for (const suf of pol.blockedHostSuffixes) {
      const s = String(suf).toLowerCase();
      if (t.host === s || t.host.endsWith('.' + s)) {
        return { decision: BC_DENY, reason: BC_REASON.HOST_BLOCKED, host: t.host };
      }
    }

    const thirdParty = !sameRegistrable(srcHost, t.host);
    if (thirdParty) {
      const whitelisted = pol.allowedHosts.some((h) => t.host === h || t.host.endsWith('.' + h));
      if (!pol.allowThirdParty && !whitelisted) {
        return { decision: BC_DENY, reason: BC_REASON.THIRD_PARTY_NOT_ALLOWED, host: t.host };
      }
    }

    const size = typeof payload === 'string' ? byteLen(payload)
      : (payload && typeof payload.byteLength === 'number' ? payload.byteLength
        : (payload && typeof payload.size === 'number' ? payload.size : 0));
    if (size > pol.maxBeaconBytes) {
      return { decision: BC_DENY, reason: BC_REASON.PAYLOAD_TOO_LARGE, bytes: size };
    }

    if (ctx.isUnloading === true) {
      const n = this.unloadCounts.get(srcHost) || 0;
      if (n >= pol.maxUnloadBeacons) {
        return { decision: BC_DENY, reason: BC_REASON.UNLOAD_FLOOD };
      }
      this.unloadCounts.set(srcHost, n + 1);
    }

    if (thirdParty && pol.stripQueryCrossOrigin) {
      return { decision: BC_STRIP, reason: BC_REASON.CROSS_ORIGIN_STRIP_QUERY, host: t.host, safeUrl: t.scheme + '://' + t.host + stripQuery(t.pathQuery) };
    }
    return { decision: BC_ALLOW, reason: '', host: t.host };
  }

  resetUnloadCount(origin) {
    this.unloadCounts.delete(originHost(origin));
  }
}

function stripQuery(pathQuery) {
  const q = pathQuery.indexOf('?');
  const h = pathQuery.indexOf('#');
  let end = pathQuery.length;
  if (q >= 0 && q < end) end = q;
  if (h >= 0 && h < end) end = h;
  return pathQuery.slice(0, end);
}

module.exports = {
  BC_ALLOW, BC_DENY, BC_STRIP, BC_REASON,
  defaultBeaconPolicy, originHost, targetSchemeHost, sameRegistrable, byteLen, BeaconGuard,
};
