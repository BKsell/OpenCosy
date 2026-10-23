'use strict';

// windownameguard.js —— window.name 跨导航泄漏与 window.opener 反向 tabnabbing 裁决内核。
//
// 威胁模型 A：window.name
//   1. window.name 在同一标签页跨域导航后仍然保留，前一个站点写入的敏感串
//      （JWT、邮箱、回跳 token）会被导航到的新站点读到；
//   2. 大量 SSO/上传组件历史上用 window.name 传值，形成事实上的跨源数据通道；
//   3. 页面写超大 name 做内存放大或塞二进制。
//
// 威胁模型 B：window.opener
//   1. target="_blank" 链接默认带 opener，新页面可用 window.opener.location
//      把原标签页跳到钓鱼站（reverse tabnabbing）；
//   2. window.open() 第三个参数传 noopener 与否需要显式裁决；
//   3. 跨源 opener 还能被用来探测原窗口是否存在/做焦点劫持。
//
// 纯逻辑模块。

const WN_DENY = 'deny';
const WN_ALLOW = 'allow';
const WN_CLEAR = 'clear';

const WN_REASON = Object.freeze({
  BAD_ORIGIN: 'wn-bad-origin',
  NAME_ON_CROSS_NAVIGATION_CLEARED: 'wn-name-cleared-on-cross-navigation',
  NAME_TOO_LARGE: 'wn-name-too-large',
  NAME_NON_STRING: 'wn-name-non-string',
  OPENER_PRESENT_CROSS_ORIGIN: 'wn-opener-present-cross-origin',
  NOOPENER_REQUIRED: 'wn-noopener-required',
  EXTERNAL_TARGET: 'wn-external-target',
});

function defaultWindowNamePolicy() {
  return {
    maxNameBytes: 2048,
    clearOnCrossOriginNavigation: true,
    requireNoopenerForExternal: true,
    allowCrossOriginOpenerAccess: false,
  };
}

function originOf(url) {
  if (typeof url !== 'string') return '';
  const colon = url.indexOf(':');
  if (colon <= 0) return '';
  const scheme = url.slice(0, colon).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  let rest = url.slice(colon + 1);
  if (rest.indexOf('//') === 0) rest = rest.slice(2);
  for (const ch of ['/', '?', '#']) {
    const p = rest.indexOf(ch);
    if (p >= 0) rest = rest.slice(0, p);
  }
  return scheme + '://' + rest.toLowerCase();
}

function sameOrigin(a, b) {
  const oa = originOf(a);
  const ob = originOf(b);
  return oa !== '' && oa === ob;
}

function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

class WindowNameGuard {
  constructor(policy) {
    this.policy = policy || defaultWindowNamePolicy();
  }

  // decideSetName 裁决页面对 window.name 的赋值。
  decideSetName(value) {
    if (typeof value !== 'string') {
      return { allowed: false, reason: WN_REASON.NAME_NON_STRING };
    }
    if (byteLen(value) > this.policy.maxNameBytes) {
      return { allowed: false, reason: WN_REASON.NAME_TOO_LARGE, bytes: byteLen(value) };
    }
    return { allowed: true, reason: '', safeName: value };
  }

  // decideNameOnNavigation 裁决跨导航后 window.name 是否还能被新页面读到。
  // from/to 为导航前后 URL；返回 effectiveName。
  decideNameOnNavigation(fromUrl, toUrl, currentName) {
    if (!this.policy.clearOnCrossOriginNavigation) {
      return { readable: true, effectiveName: currentName, reason: '' };
    }
    if (sameOrigin(fromUrl, toUrl)) {
      return { readable: true, effectiveName: currentName, reason: '' };
    }
    return { readable: false, effectiveName: '', reason: WN_REASON.NAME_ON_CROSS_NAVIGATION_CLEARED };
  }

  // decideOpen 裁决 window.open / a[target=_blank] 是否需要 noopener。
  // ctx: {sourceUrl, targetUrl, hasNoopener, hasNoreferrer}
  decideOpen(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return { allowed: false, reason: WN_REASON.BAD_ORIGIN };
    const src = originOf(ctx.sourceUrl);
    const dst = originOf(ctx.targetUrl);
    if (!src) return { allowed: false, reason: WN_REASON.BAD_ORIGIN };
    const cross = src !== dst && dst !== '';
    // 跨源或外部目标必须 noopener（noreferrer 在多数浏览器里隐含 noopener）。
    if (cross || (dst === '')) {
      const safe = ctx.hasNoopener === true || ctx.hasNoreferrer === true;
      if (pol.requireNoopenerForExternal && !safe) {
        return {
          allowed: true,
          forceNoopener: true,
          crossOrigin: cross,
          reason: cross ? WN_REASON.OPENER_PRESENT_CROSS_ORIGIN : WN_REASON.EXTERNAL_TARGET,
        };
      }
      if (!pol.allowCrossOriginOpenerAccess && cross && !safe) {
        return { allowed: true, forceNoopener: true, crossOrigin: true, reason: WN_REASON.NOOPENER_REQUIRED };
      }
    }
    return { allowed: true, forceNoopener: false, crossOrigin: cross, reason: '' };
  }

  // decideOpenerAccess 裁决新文档通过 window.opener 访问原窗口。
  decideOpenerAccess(openerUrl, currentUrl) {
    const o = originOf(openerUrl);
    const c = originOf(currentUrl);
    if (!o || !c) return { access: false, reason: WN_REASON.BAD_ORIGIN };
    if (o === c) return { access: true, reason: '' };
    if (this.policy.allowCrossOriginOpenerAccess) return { access: true, reason: '' };
    return { access: false, reason: WN_REASON.OPENER_PRESENT_CROSS_ORIGIN };
  }
}

module.exports = {
  WN_ALLOW, WN_DENY, WN_CLEAR, WN_REASON,
  defaultWindowNamePolicy, originOf, sameOrigin, byteLen, WindowNameGuard,
};
