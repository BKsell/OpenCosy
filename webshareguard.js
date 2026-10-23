'use strict';

// webshareguard.js —— Web Share API（navigator.share / canShare）外发数据裁决内核。
//
// 威胁模型：
//   1. share() 会把页面提供的文本/URL/文件交给系统分享面板或其它 App：恶意页把伪造的钓鱼
//      链接、诈骗文案塞进分享内容，借用户之手投递给通讯录；或把 file 句柄中的本地文件外发；
//   2. 分享 javascript:/data: URL，或文本里夹带凭证/令牌；URL 与显示文本不一致（超链接伪装）；
//   3. 无手势/不可见调用，或对超大文本/可执行文件类型做分享；
//   4. 文件分享绕过下载 MOTW 直接交给原生 App；
//   5. 后台高频调用诱导误分享。
//
// 纯逻辑。

const WS_ALLOW = 'allow';
const WS_DENY = 'deny';

const WS_REASON = Object.freeze({
  BAD_CONTEXT: 'ws-bad-context',
  INSECURE_ORIGIN: 'ws-insecure-origin',
  NO_GESTURE: 'ws-no-gesture',
  NOT_VISIBLE: 'ws-not-visible',
  EMPTY_SHARE: 'ws-empty-share',
  BAD_URL_SCHEME: 'ws-bad-url-scheme',
  URL_TEXT_MISMATCH: 'ws-url-text-mismatch',
  TEXT_TOO_LARGE: 'ws-text-too-large',
  FILE_TYPE_BLOCKED: 'ws-file-type-blocked',
  FILE_TOO_LARGE: 'ws-file-too-large',
  TOO_MANY_FILES: 'ws-too-many-files',
  RATE_LIMIT: 'ws-rate-limit',
});

const WS_BLOCKED_URL_SCHEMES = Object.freeze(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:']);
const WS_BLOCKED_FILE_EXT = Object.freeze([
  'exe', 'msi', 'bat', 'cmd', 'ps1', 'scr', 'com', 'jar', 'app', 'sh', 'dll', 'lnk', 'apk',
]);

function defaultWebSharePolicy() {
  return {
    requireHttps: true,
    requireUserGesture: true,
    requireVisible: true,
    maxTextBytes: 4096,
    maxTitleBytes: 256,
    maxFiles: 4,
    maxFileBytes: 25 * 1024 * 1024,
    blockedFileExtensions: WS_BLOCKED_FILE_EXT.slice(),
    maxSharesPerMinute: 6,
    requireUrlInText: false,
  };
}

function schemeOf(s) {
  if (typeof s !== 'string') return '';
  const c = s.indexOf(':');
  return c > 0 ? s.slice(0, c).toLowerCase() : '';
}
function byteLen(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}
function lower(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += (c >= 65 && c <= 90) ? String.fromCharCode(c + 32) : s.charAt(i);
  }
  return out;
}
function extOf(name) {
  if (typeof name !== 'string') return '';
  const dot = name.lastIndexOf('.');
  return dot >= 0 ? lower(name.slice(dot + 1)) : '';
}
function trimSpaces(s) {
  let a = 0;
  let b = s.length;
  while (a < b && (s.charAt(a) === ' ' || s.charCodeAt(a) <= 0x20)) a++;
  while (b > a && (s.charAt(b - 1) === ' ' || s.charCodeAt(b - 1) <= 0x20)) b--;
  return s.slice(a, b);
}

class WebShareGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultWebSharePolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.times = [];
  }

  // decideShare 裁决 navigator.share(data)。
  // data: {title, text, url, files:[{name, sizeBytes}]}
  decideShare(ctx, data) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return { decision: WS_DENY, reason: WS_REASON.BAD_CONTEXT };
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return { decision: WS_DENY, reason: WS_REASON.INSECURE_ORIGIN };
    if (pol.requireUserGesture && ctx.userGesture !== true) return { decision: WS_DENY, reason: WS_REASON.NO_GESTURE };
    if (pol.requireVisible && ctx.visible === false) return { decision: WS_DENY, reason: WS_REASON.NOT_VISIBLE };

    const d = data && typeof data === 'object' ? data : {};
    const hasText = typeof d.text === 'string' && d.text.length > 0;
    const hasUrl = typeof d.url === 'string' && d.url.length > 0;
    const hasTitle = typeof d.title === 'string' && d.title.length > 0;
    const hasFiles = Array.isArray(d.files) && d.files.length > 0;
    if (!hasText && !hasUrl && !hasTitle && !hasFiles) return { decision: WS_DENY, reason: WS_REASON.EMPTY_SHARE };

    if (typeof d.title === 'string' && byteLen(d.title) > pol.maxTitleBytes) {
      return { decision: WS_DENY, reason: WS_REASON.TEXT_TOO_LARGE, field: 'title' };
    }
    if (typeof d.text === 'string' && byteLen(d.text) > pol.maxTextBytes) {
      return { decision: WS_DENY, reason: WS_REASON.TEXT_TOO_LARGE, field: 'text' };
    }
    if (hasUrl) {
      const sch = schemeOf(d.url);
      if (WS_BLOCKED_URL_SCHEMES.indexOf(sch + ':') >= 0 || (sch !== 'https' && sch !== 'http')) {
        return { decision: WS_DENY, reason: WS_REASON.BAD_URL_SCHEME, scheme: sch };
      }
      // 若文本里只放了一个不同的 http(s) 链接，提示超链接伪装。
      if (hasText && pol.requireUrlInText && trimSpaces(d.text).indexOf(d.url) < 0) {
        return { decision: WS_DENY, reason: WS_REASON.URL_TEXT_MISMATCH };
      }
    }

    if (hasFiles) {
      if (d.files.length > pol.maxFiles) return { decision: WS_DENY, reason: WS_REASON.TOO_MANY_FILES, count: d.files.length };
      for (const f of d.files) {
        const ext = extOf(f && f.name);
        if (pol.blockedFileExtensions.indexOf(ext) >= 0) {
          return { decision: WS_DENY, reason: WS_REASON.FILE_TYPE_BLOCKED, ext };
        }
        if (f && typeof f.sizeBytes === 'number' && f.sizeBytes > pol.maxFileBytes) {
          return { decision: WS_DENY, reason: WS_REASON.FILE_TOO_LARGE, name: f.name };
        }
      }
    }

    const now = this.clock();
    this.times = this.times.filter((t) => now - t < 60000);
    if (this.times.length >= pol.maxSharesPerMinute) return { decision: WS_DENY, reason: WS_REASON.RATE_LIMIT };
    this.times.push(now);
    return { decision: WS_ALLOW, reason: '' };
  }
}

module.exports = {
  WS_ALLOW, WS_DENY, WS_REASON, WS_BLOCKED_URL_SCHEMES, WS_BLOCKED_FILE_EXT,
  defaultWebSharePolicy, extOf, WebShareGuard,
};
