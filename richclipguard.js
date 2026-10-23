'use strict';

// richclipguard.js —— Async Clipboard 富文本/图片读取与写入裁决内核（区别于既有 clipboardguard 文本面）。
//
// 威胁模型：
//   1. clipboard.read() 可在用户此前"复制"了密码/助记词/卡号后，被下一标签（或被劫持页面）
//      静默读出，剪贴板是跨站数据汇聚点；
//   2. read({unsanitized:'html'}) 取回原始 HTML（含 javascript:、on* 处理器、追踪像素），
//      再被 innerHTML 注入即存储型 XSS；
//   3. 粘贴图片/富文本携带巨量 payload 做内存耗尽；
//   4. 后台/不可见文档轮询剪贴板做内容监控；
//   5. writeText 把攻击者内容覆盖用户刚复制的钱包地址（剪贴币址替换）。
//
// 纯逻辑。

const RC_ALLOW = 'allow';
const RC_DENY = 'deny';

const RC_REASON = Object.freeze({
  BAD_CONTEXT: 'rc-bad-context',
  INSECURE_ORIGIN: 'rc-insecure-origin',
  READ_DISABLED: 'rc-read-disabled',
  NO_GESTURE: 'rc-no-gesture',
  NOT_VISIBLE: 'rc-not-visible',
  UNSANITIZED_HTML: 'rc-unsanitized-html',
  SCRIPT_IN_HTML: 'rc-script-in-html',
  PAYLOAD_TOO_LARGE: 'rc-payload-too-large',
  UNKNOWN_MIME: 'rc-unknown-mime',
  RATE_LIMIT: 'rc-rate-limit',
});

// 常见富文本中危险片段（纯小写子串匹配，不用正则）。
const RC_HTML_DANGER = Object.freeze([
  '<script', 'javascript:', '<iframe', '<object', '<embed', 'onerror',
  'onload', 'onclick', 'onmouseover', 'srcdoc', 'data:text/html',
]);

function defaultRichClipPolicy() {
  return {
    requireHttps: true,
    allowRead: true,
    requireUserGestureForRead: true,
    requireVisible: true,
    allowUnsanitizedHtml: false,
    sanitizeHtmlOnRead: true,
    maxTextBytes: 1 * 1024 * 1024,
    maxImageBytes: 10 * 1024 * 1024,
    allowedMimePrefixes: ['text/plain', 'text/html', 'image/png', 'image/jpeg', 'image/webp', 'image/gif'],
    maxReadsPerMinute: 30,
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
function lower(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    out += (c >= 65 && c <= 90) ? String.fromCharCode(c + 32) : s.charAt(i);
  }
  return out;
}
function containsDangerousHtml(html) {
  const h = lower(html);
  for (const frag of RC_HTML_DANGER) {
    if (h.indexOf(frag) >= 0) return frag;
  }
  return '';
}

class RichClipGuard {
  constructor(policy, clock) {
    this.policy = policy || defaultRichClipPolicy();
    this.clock = typeof clock === 'function' ? clock : (() => Date.now());
    this.readTimes = [];
  }

  _gateRead(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object' || typeof ctx.origin !== 'string') return RC_REASON.BAD_CONTEXT;
    if (pol.requireHttps && ctx.origin.indexOf('https://') !== 0) return RC_REASON.INSECURE_ORIGIN;
    if (!pol.allowRead) return RC_REASON.READ_DISABLED;
    if (pol.requireUserGestureForRead && ctx.userGesture !== true) return RC_REASON.NO_GESTURE;
    if (pol.requireVisible && ctx.visible === false) return RC_REASON.NOT_VISIBLE;
    return '';
  }
  _rateLimited() {
    const now = this.clock();
    this.readTimes = this.readTimes.filter((t) => now - t < 60000);
    if (this.readTimes.length >= this.policy.maxReadsPerMinute) return true;
    this.readTimes.push(now);
    return false;
  }

  // decideReadText 裁决 readText。
  decideReadText(ctx) {
    const bad = this._gateRead(ctx);
    if (bad) return { decision: RC_DENY, reason: bad };
    if (this._rateLimited()) return { decision: RC_DENY, reason: RC_REASON.RATE_LIMIT };
    return { decision: RC_ALLOW, reason: '' };
  }

  // decideRead 裁决 read(options) 与随后粘贴进来的富文本项。
  // item: {type, text, sizeBytes, unsanitized}
  decideRead(ctx, item, options) {
    const bad = this._gateRead(ctx);
    if (bad) return { decision: RC_DENY, reason: bad };
    const pol = this.policy;
    const opt = options && typeof options === 'object' ? options : {};
    if (opt.unsanitized === 'html' && !pol.allowUnsanitizedHtml) {
      return { decision: RC_DENY, reason: RC_REASON.UNSANITIZED_HTML };
    }
    if (this._rateLimited()) return { decision: RC_DENY, reason: RC_REASON.RATE_LIMIT };
    if (!item || typeof item.type !== 'string') return { decision: RC_DENY, reason: RC_REASON.UNKNOWN_MIME };

    const okMime = pol.allowedMimePrefixes.some((m) => item.type.indexOf(m) === 0);
    if (!okMime) return { decision: RC_DENY, reason: RC_REASON.UNKNOWN_MIME, type: item.type };

    if (item.type.indexOf('image/') === 0) {
      if (typeof item.sizeBytes === 'number' && item.sizeBytes > pol.maxImageBytes) {
        return { decision: RC_DENY, reason: RC_REASON.PAYLOAD_TOO_LARGE, size: item.sizeBytes };
      }
      return { decision: RC_ALLOW, reason: '' };
    }
    const text = typeof item.text === 'string' ? item.text : '';
    if (byteLen(text) > pol.maxTextBytes) return { decision: RC_DENY, reason: RC_REASON.PAYLOAD_TOO_LARGE };
    if (item.type.indexOf('text/html') === 0) {
      const wantRaw = opt.unsanitized === 'html' || item.unsanitized === true;
      if (wantRaw && !pol.allowUnsanitizedHtml) return { decision: RC_DENY, reason: RC_REASON.UNSANITIZED_HTML };
      const frag = containsDangerousHtml(text);
      if (frag && (!pol.sanitizeHtmlOnRead || wantRaw)) {
        return { decision: RC_DENY, reason: RC_REASON.SCRIPT_IN_HTML, fragment: frag };
      }
    }
    return { decision: RC_ALLOW, reason: '' };
  }
}

module.exports = {
  RC_ALLOW, RC_DENY, RC_REASON, RC_HTML_DANGER,
  defaultRichClipPolicy, byteLen, containsDangerousHtml, RichClipGuard,
};
