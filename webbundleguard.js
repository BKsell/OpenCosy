'use strict';

// webbundleguard.js —— Web Bundles / Subresource Bundles（<link rel="webbundle">）裁决内核。
//
// 威胁模型：
//   1. Web Bundle（.wbn）是一个把多个子资源打包的容器，页面通过 resources URL 列表声明从
//      bundle 内取用哪些地址：若允许 http/私网/第三方来源，攻击者可用一个 bundle 把内部资源、
//      跨站脚本一并塞进可信页面的资源解析，形成来源混淆与本地资源替换；
//   2. resources 里声明将被"本地满足"的 URL 可包括脚本，bundle 内脚本能以宿主源执行 → XSS；
//   3. scopes 过宽（整源 /）让 bundle 劫持后续所有子资源；
//   4. 巨大 resources 列表 / 非 https bundle URL / 跨站 bundle 无完整性校验；
//   5. 非安全上下文。
//
// 纯逻辑。

const WBB_ALLOW = 'allow';
const WBB_DENY = 'deny';

const WBB_REASON = Object.freeze({
  BAD_CONTEXT: 'wbb-bad-context',
  INSECURE_ORIGIN: 'wbb-insecure-origin',
  BAD_BUNDLE_URL: 'wbb-bad-bundle-url',
  BUNDLE_CROSS_ORIGIN: 'wbb-bundle-cross-origin',
  MISSING_INTEGRITY: 'wbb-missing-integrity',
  NO_RESOURCES: 'wbb-no-resources',
  TOO_MANY_RESOURCES: 'wbb-too-many-resources',
  INSECURE_RESOURCE: 'wbb-insecure-resource',
  RESOURCE_CROSS_SITE: 'wbb-resource-cross-site',
  RESOURCE_PRIVATE: 'wbb-resource-private',
  SCRIPT_FROM_BUNDLE: 'wbb-script-from-bundle',
  SCOPE_TOO_WIDE: 'wbb-scope-too-wide',
});

function defaultWebBundlePolicy() {
  return {
    requireHttps: true,
    requireSameOriginBundle: true,
    requireIntegrityForCrossOrigin: true,
    maxResources: 32,
    blockPrivateResources: true,
    allowScriptResources: false,
    allowRootScope: false,
    maxScopeDepth: 3,
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
  if (rest.indexOf('[') !== 0) {
    const pc = rest.lastIndexOf(':');
    if (pc > 0) rest = rest.slice(0, pc);
  }
  return rest.toLowerCase();
}
function regSite(host) {
  const labels = host.split('.');
  return labels.length >= 2 ? labels.slice(-2).join('.') : host;
}
function pathOf(url) {
  if (typeof url !== 'string') return '';
  const i = url.indexOf('://');
  if (i <= 0) return '';
  let rest = url.slice(i + 3);
  const slash = rest.indexOf('/');
  return slash >= 0 ? rest.slice(slash) : '/';
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
function isScriptUrl(url) {
  const path = pathOf(url).toLowerCase();
  const q = path.indexOf('?');
  const p = q >= 0 ? path.slice(0, q) : path;
  for (const ext of ['.js', '.mjs', '.cjs']) {
    if (p.endsWith(ext)) return true;
  }
  return false;
}

class WebBundleGuard {
  constructor(policy) {
    this.policy = policy || defaultWebBundlePolicy();
  }

  // decideLink 裁决 <link rel="webbundle" href resources scopes integrity>。
  decideLink(ctx, spec) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: WBB_DENY, reason: WBB_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: WBB_DENY, reason: WBB_REASON.INSECURE_ORIGIN };
    const s = spec && typeof spec === 'object' ? spec : {};

    const href = s.href;
    if (schemeOf(href) !== 'https') return { decision: WBB_DENY, reason: WBB_REASON.BAD_BUNDLE_URL, href };
    const bundleHost = hostOf(href);
    const pageHost = hostOf(ctx.origin);
    const crossOrigin = regSite(bundleHost) !== regSite(pageHost);
    if (crossOrigin && pol.requireSameOriginBundle) return { decision: WBB_DENY, reason: WBB_REASON.BUNDLE_CROSS_ORIGIN, host: bundleHost };
    if (crossOrigin && pol.requireIntegrityForCrossOrigin && typeof s.integrity !== 'string') {
      return { decision: WBB_DENY, reason: WBB_REASON.MISSING_INTEGRITY };
    }

    const resources = Array.isArray(s.resources) ? s.resources : [];
    if (resources.length === 0) return { decision: WBB_DENY, reason: WBB_REASON.NO_RESOURCES };
    if (resources.length > pol.maxResources) return { decision: WBB_DENY, reason: WBB_REASON.TOO_MANY_RESOURCES, count: resources.length };

    for (const u of resources) {
      if (schemeOf(u) !== 'https') return { decision: WBB_DENY, reason: WBB_REASON.INSECURE_RESOURCE, url: u };
      if (pol.blockPrivateResources && isPrivateHost(hostOf(u))) {
        return { decision: WBB_DENY, reason: WBB_REASON.RESOURCE_PRIVATE, url: u };
      }
      if (regSite(hostOf(u)) !== regSite(pageHost)) {
        return { decision: WBB_DENY, reason: WBB_REASON.RESOURCE_CROSS_SITE, url: u };
      }
      if (!pol.allowScriptResources && isScriptUrl(u)) {
        return { decision: WBB_DENY, reason: WBB_REASON.SCRIPT_FROM_BUNDLE, url: u };
      }
    }

    const scopes = Array.isArray(s.scopes) ? s.scopes : [];
    for (const sc of scopes) {
      const path = pathOf(sc);
      if (path === '/' || path === '') {
        if (!pol.allowRootScope) return { decision: WBB_DENY, reason: WBB_REASON.SCOPE_TOO_WIDE, scope: sc };
      }
      const depth = path.split('/').filter((seg) => seg.length > 0).length;
      if (depth > pol.maxScopeDepth) return { decision: WBB_DENY, reason: WBB_REASON.SCOPE_TOO_WIDE, scope: sc };
    }
    return { decision: WBB_ALLOW, reason: '' };
  }
}

module.exports = {
  WBB_ALLOW, WBB_DENY, WBB_REASON,
  defaultWebBundlePolicy, hostOf, isPrivateHost, isScriptUrl, WebBundleGuard,
};
