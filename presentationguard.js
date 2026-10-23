'use strict';

// presentationguard.js —— Presentation API（PresentationRequest / start）投屏到第二屏裁决内核。
//
// 威胁模型：
//   1. Presentation API 让页面把内容投到同一局域网的 Chromecast/智能屏/演示接收器：URL 完全
//      可控，可把受害者电视导向钓鱼/内网管理页，或借接收器对内网发起请求（SSRF 的投屏面）；
//   2. presentationUrls 里塞 http、私网/环回/设备多播地址；或 cast: 等非 https scheme；
//   3. reconnect 复用既有 presentation id 做会话劫持；无手势自动开始投屏；
//   4. 海量候选 URL 对内网主机做存活扫描；
//   5. 非安全上下文。
//
// 纯逻辑。

const PG_ALLOW = 'allow';
const PG_DENY = 'deny';

const PG_REASON = Object.freeze({
  BAD_CONTEXT: 'pg-bad-context',
  INSECURE_ORIGIN: 'pg-insecure-origin',
  NO_GESTURE: 'pg-no-gesture',
  NO_URLS: 'pg-no-urls',
  TOO_MANY_URLS: 'pg-too-many-urls',
  BAD_URL_SCHEME: 'pg-bad-url-scheme',
  TARGET_PRIVATE: 'pg-target-private',
  RECONNECT_DISABLED: 'pg-reconnect-disabled',
  BAD_PRESENTATION_ID: 'pg-bad-presentation-id',
});

function defaultPresentationPolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    maxPresentationUrls: 4,
    blockPrivateTargets: true,
    allowReconnect: false,
    maxPresentationIdBytes: 128,
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
  if (a >= 224) return true; // 组播/保留（含 SSDP/mDNS 邻近发现段的多播起始）
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

class PresentationGuard {
  constructor(policy) {
    this.policy = policy || defaultPresentationPolicy();
  }

  // decideStart 裁决 new PresentationRequest(urls).start() 或 reconnect(id)。
  // action: 'start' | 'reconnect'
  decideStart(ctx, action, urls, presentationId) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: PG_DENY, reason: PG_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: PG_DENY, reason: PG_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: PG_DENY, reason: PG_REASON.NO_GESTURE };

    if (action === 'reconnect') {
      if (!pol.allowReconnect) return { decision: PG_DENY, reason: PG_REASON.RECONNECT_DISABLED };
      const id = presentationId;
      if (typeof id !== 'string' || id.length === 0 || byteLen(id) > pol.maxPresentationIdBytes || hasControlChar(id)) {
        return { decision: PG_DENY, reason: PG_REASON.BAD_PRESENTATION_ID };
      }
      return { decision: PG_ALLOW, reason: '' };
    }

    if (!Array.isArray(urls) || urls.length === 0) return { decision: PG_DENY, reason: PG_REASON.NO_URLS };
    if (urls.length > pol.maxPresentationUrls) return { decision: PG_DENY, reason: PG_REASON.TOO_MANY_URLS, count: urls.length };
    for (const u of urls) {
      if (schemeOf(u) !== 'https') return { decision: PG_DENY, reason: PG_REASON.BAD_URL_SCHEME, url: u };
      if (pol.blockPrivateTargets && isPrivateHost(hostOf(u))) {
        return { decision: PG_DENY, reason: PG_REASON.TARGET_PRIVATE, url: u };
      }
    }
    return { decision: PG_ALLOW, reason: '' };
  }
}

module.exports = {
  PG_ALLOW, PG_DENY, PG_REASON,
  defaultPresentationPolicy, schemeOf, hostOf, isPrivateHost, PresentationGuard,
};
