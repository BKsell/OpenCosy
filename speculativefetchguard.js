'use strict';

// speculativefetchguard.js —— Speculation Rules（prefetch/prerender）+ DNS 预解析裁决内核。
//
// 威胁模型：
//   1. <script type="speculationrules"> 让浏览器在用户未点击时就预取/预渲染第三方 URL，
//      等于由页面代为发起跨站请求：带出 Cookie、做网络侧打点、对内网地址形成 SSRF 面；
//   2. prerender 在隐藏文档里执行脚本、可申请部分能力，用户"还没访问"站点却已运行代码；
//   3. "eagerness":"eager" + 大列表构成推测洪水，耗尽带宽并向大量主机泄露浏览意图；
//   4. 预解析 dns-prefetch/preconnect 到内网/环回可做内网主机存活探测；
//   5. requires 匿名跨站（anonymous-client-ip）若被忽略，预渲染会带真实 IP。
//
// 纯逻辑：对单条 speculation rule 与单个预取目标做裁决。

const SF_ALLOW = 'allow';
const SF_DENY = 'deny';

const SF_REASON = Object.freeze({
  BAD_CONTEXT: 'sf-bad-context',
  INSECURE_ORIGIN: 'sf-insecure-origin',
  BAD_RULE: 'sf-bad-rule',
  UNKNOWN_ACTION: 'sf-unknown-action',
  PRERENDER_DISABLED: 'sf-prerender-disabled',
  INSECURE_TARGET: 'sf-insecure-target',
  TARGET_PRIVATE_ADDRESS: 'sf-target-private-address',
  TARGET_TOO_MANY: 'sf-target-too-many',
  EAGER_DISABLED: 'sf-eager-disabled',
  ANONYMIZATION_REQUIRED: 'sf-anonymization-required',
  PREFETCH_WITHOUT_REFERRER_POLICY: 'sf-prefetch-without-referrer-policy',
});

function defaultSpeculativePolicy() {
  return {
    requireHttps: true,
    allowPrefetch: true,
    allowPrerender: false,
    maxTargetsPerRule: 10,
    blockEager: true,
    requireHttpsTargets: true,
    blockPrivateTargets: true,
    requireAnonymousCrossOrigin: true,
  };
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
function schemeOf(url) {
  if (typeof url !== 'string') return '';
  const c = url.indexOf(':');
  return c > 0 ? url.slice(0, c).toLowerCase() : '';
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
  if (host === 'localhost' || host.slice(-10) === '.localhost') return true;
  const ip = parseIpv4(host);
  if (ip === null) return false;
  const a = Math.floor(ip / 0x1000000) & 0xff;
  const b = (ip >> 16) & 0xff;
  if (a === 127 || a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

class SpeculativeFetchGuard {
  constructor(policy) {
    this.policy = policy || defaultSpeculativePolicy();
  }

  _gate(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return SF_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return SF_REASON.INSECURE_ORIGIN;
    return '';
  }

  // decideRule 裁决一条 speculation rule。
  // rule: {action:'prefetch'|'prerender', eagerness, requires:['anonymous-client-ip'],
  //   referrerPolicy, source:'list'|'document', urls:[...], targetRelations:[...]}
  decideRule(ctx, rule) {
    const bad = this._gate(ctx);
    if (bad) return { decision: SF_DENY, reason: bad };
    const pol = this.policy;
    if (!rule || typeof rule !== 'object') return { decision: SF_DENY, reason: SF_REASON.BAD_RULE };
    const action = rule.action;
    if (action !== 'prefetch' && action !== 'prerender') return { decision: SF_DENY, reason: SF_REASON.UNKNOWN_ACTION };
    if (action === 'prerender' && !pol.allowPrerender) return { decision: SF_DENY, reason: SF_REASON.PRERENDER_DISABLED };

    if (pol.blockEager && rule.eagerness === 'eager') return { decision: SF_DENY, reason: SF_REASON.EAGER_DISABLED };

    const urls = Array.isArray(rule.urls) ? rule.urls : [];
    if (urls.length === 0 && rule.source !== 'document') return { decision: SF_DENY, reason: SF_REASON.BAD_RULE };
    if (urls.length > pol.maxTargetsPerRule) return { decision: SF_DENY, reason: SF_REASON.TARGET_TOO_MANY, count: urls.length };

    for (const u of urls) {
      const sch = schemeOf(u);
      if (sch !== 'https' && sch !== 'http') return { decision: SF_DENY, reason: SF_REASON.BAD_RULE, url: u };
      if (pol.requireHttpsTargets && sch !== 'https') return { decision: SF_DENY, reason: SF_REASON.INSECURE_TARGET, url: u };
      if (pol.blockPrivateTargets && isPrivateHost(hostOf(u))) {
        return { decision: SF_DENY, reason: SF_REASON.TARGET_PRIVATE_ADDRESS, url: u, host: hostOf(u) };
      }
    }

    const crossSite = this._anyCrossSite(urls, ctx.origin);
    if (crossSite && pol.requireAnonymousCrossOrigin &&
        (!Array.isArray(rule.requires) || rule.requires.indexOf('anonymous-client-ip') < 0)) {
      return { decision: SF_DENY, reason: SF_REASON.ANONYMIZATION_REQUIRED };
    }
    if (action === 'prefetch' && crossSite &&
        (rule.referrerPolicy === undefined || rule.referrerPolicy === 'unsafe-url' || rule.referrerPolicy === '')) {
      return { decision: SF_DENY, reason: SF_REASON.PREFETCH_WITHOUT_REFERRER_POLICY };
    }
    return { decision: SF_ALLOW, reason: '' };
  }

  _anyCrossSite(urls, origin) {
    const myHost = hostOf(origin);
    const myReg = myHost.split('.').slice(-2).join('.');
    for (const u of urls) {
      const h = hostOf(u);
      const reg = h.split('.').slice(-2).join('.');
      if (reg && reg !== myReg) return true;
    }
    return false;
  }
}

module.exports = {
  SF_ALLOW, SF_DENY, SF_REASON,
  defaultSpeculativePolicy, hostOf, schemeOf, parseIpv4, isPrivateHost, SpeculativeFetchGuard,
};
