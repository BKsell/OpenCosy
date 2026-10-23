'use strict';

// backgroundfetchguard.js —— Background Fetch API（BackgroundFetchManager.fetch，Service Worker 大文件）
// 长时间后台下载裁决内核。
//
// 威胁模型：
//   1. Background Fetch 可在页面/标签关闭后由浏览器持续下载大文件，成为隐蔽出网通道：
//      SW 静默拉取大量数据到站点来源，用户无感知，可被用来做数据渗出后的回传，或把浏览器
//      变成长期下载肉鸡；
//   2. downloadTotal 虚报（声明很小、实际响应巨大）绕过配额；
//   3. 目标 URL 指向内网/环回（配合已安装 SW 的源）形成后台 SSRF；
//   4. icons/title 用超长/控制字符脏数据；多请求 request 列表无界；
//   5. 非 https、非安全上下文发起。
//
// 纯逻辑。

const BF_ALLOW = 'allow';
const BF_DENY = 'deny';

const BF_REASON = Object.freeze({
  BAD_CONTEXT: 'bf-bad-context',
  INSECURE_ORIGIN: 'bf-insecure-origin',
  NOT_INSTALLED: 'bf-not-installed',
  NO_REQUESTS: 'bf-no-requests',
  TOO_MANY_REQUESTS: 'bf-too-many-requests',
  BAD_TOTAL: 'bf-bad-total',
  TOTAL_TOO_LARGE: 'bf-total-too-large',
  TOTAL_UNDERREPORTED: 'bf-total-underreported',
  INSECURE_TARGET: 'bf-insecure-target',
  TARGET_PRIVATE: 'bf-target-private',
  BAD_TITLE_ICON: 'bf-bad-title-icon',
  CONCURRENT_FETCHES: 'bf-concurrent-fetches',
});

function defaultBackgroundFetchPolicy() {
  return {
    requireHttps: true,
    requireInstalledServiceWorker: true,
    maxRequestsPerFetch: 8,
    maxDownloadTotalBytes: 500 * 1024 * 1024,
    maxTitleBytes: 256,
    maxIcons: 6,
    maxConcurrentPerOrigin: 2,
    blockPrivateTargets: true,
  };
}

function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const c = url.indexOf(':');
  return c > 0 ? url.slice(0, c).toLowerCase() : '';
}
function hostOf(url) {
  if (typeof url !== 'string') return '';
  const i = url.indexOf('://');
  if (i <= 0) return '';
  let rest = url.slice(i + 3);
  for (const ch of ['/', '?', '#']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  if (rest.indexOf('@') >= 0) rest = rest.slice(rest.lastIndexOf('@') + 1);
  if (rest.indexOf('[') === 0) {
    const rb = rest.indexOf(']');
    rest = rb > 0 ? rest.slice(1, rb) : rest;
  } else {
    const pc = rest.lastIndexOf(':');
    if (pc > 0) rest = rest.slice(0, pc);
  }
  return rest.toLowerCase();
}
function parseIpv4(host) {
  const parts = host.split('.');
  if (parts.length !== 4) return null;
  let ip = 0;
  for (const seg of parts) {
    if (seg.length === 0 || seg.length > 3) return null;
    for (let i = 0; i < seg.length; i++) {
      const c = seg.charCodeAt(i);
      if (c < 48 || c > 57) return null;
    }
    const v = Number(seg);
    if (v > 255) return null;
    ip = ip * 256 + v;
  }
  return ip;
}
function isPrivateHost(host) {
  if (host === 'localhost' || host.slice(-10) === '.localhost' || host.slice(-6) === '.local') return true;
  const ip = parseIpv4(host);
  if (ip === null) return false;
  const a = (ip >>> 24) & 255;
  const b = (ip >>> 16) & 255;
  if (a === 0 || a === 127 || a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
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

class BackgroundFetchGuard {
  constructor(policy) {
    this.policy = policy || defaultBackgroundFetchPolicy();
    this.active = new Map();
  }

  // decideFetch 裁决 manager.fetch(id, requests, options)。
  // requests: [url 或 {url}]；options: {downloadTotal, title, icons:[...]}
  // ctx: {origin, serviceWorkerActive}
  decideFetch(ctx, id, requests, options, actualTotal) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: BF_DENY, reason: BF_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: BF_DENY, reason: BF_REASON.INSECURE_ORIGIN };
    if (pol.requireInstalledServiceWorker && ctx.serviceWorkerActive !== true) {
      return { decision: BF_DENY, reason: BF_REASON.NOT_INSTALLED };
    }
    if (!Array.isArray(requests) || requests.length === 0) return { decision: BF_DENY, reason: BF_REASON.NO_REQUESTS };
    if (requests.length > pol.maxRequestsPerFetch) return { decision: BF_DENY, reason: BF_REASON.TOO_MANY_REQUESTS, count: requests.length };

    const n = this.active.get(ctx.origin) || 0;
    if (n >= pol.maxConcurrentPerOrigin) return { decision: BF_DENY, reason: BF_REASON.CONCURRENT_FETCHES };

    const opt = options && typeof options === 'object' ? options : {};
    const total = opt.downloadTotal;
    if (typeof total !== 'number' || !Number.isFinite(total) || total < 0) {
      return { decision: BF_DENY, reason: BF_REASON.BAD_TOTAL };
    }
    if (total > pol.maxDownloadTotalBytes) return { decision: BF_DENY, reason: BF_REASON.TOTAL_TOO_LARGE, total };
    // 实际响应体若已知，且显著超过声明（>10%），判虚报。
    if (typeof actualTotal === 'number' && actualTotal > total * 1.1) {
      return { decision: BF_DENY, reason: BF_REASON.TOTAL_UNDERREPORTED, declared: total, actual: actualTotal };
    }

    if (typeof opt.title === 'string') {
      if (byteLen(opt.title) > pol.maxTitleBytes || hasControlChar(opt.title)) {
        return { decision: BF_DENY, reason: BF_REASON.BAD_TITLE_ICON, field: 'title' };
      }
    }
    if (Array.isArray(opt.icons)) {
      if (opt.icons.length > pol.maxIcons) return { decision: BF_DENY, reason: BF_REASON.BAD_TITLE_ICON, field: 'icons' };
      for (const ic of opt.icons) {
        const src = ic && ic.src;
        if (typeof src !== 'string' || schemeOf(src) !== 'https') {
          return { decision: BF_DENY, reason: BF_REASON.BAD_TITLE_ICON, field: 'icon-src' };
        }
      }
    }

    for (const req of requests) {
      const url = typeof req === 'string' ? req : (req && req.url);
      if (schemeOf(url) !== 'https') return { decision: BF_DENY, reason: BF_REASON.INSECURE_TARGET, url };
      if (pol.blockPrivateTargets && isPrivateHost(hostOf(url))) {
        return { decision: BF_DENY, reason: BF_REASON.TARGET_PRIVATE, url };
      }
    }

    this.active.set(ctx.origin, n + 1);
    return { decision: BF_ALLOW, reason: '', fetchId: id };
  }

  finish(ctx) {
    const n = this.active.get(ctx.origin) || 0;
    if (n > 0) this.active.set(ctx.origin, n - 1);
  }
}

module.exports = {
  BF_ALLOW, BF_DENY, BF_REASON,
  defaultBackgroundFetchPolicy, schemeOf, hostOf, isPrivateHost, byteLen, BackgroundFetchGuard,
};
