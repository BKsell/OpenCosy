'use strict';

// selectionguard.js —— copy/cut/selectstart 与写入剪贴板内容的安全裁决内核。
//
// 威胁模型：
//   1. 复制劫持：页面监听 copy 并 preventDefault + setData，把用户选中的文字换成
//      带追踪参数的链接、广告文本，甚至 javascript:/data: URL，用户粘贴进终端、
//      地址栏或富文本框即触发；
//     典型攻击是“复制正常文字 → 剪贴板被换成恶意命令”。
//   2. HTML 剪贴板注入：text/html 里夹带 <script>、on* 句柄、javascript:href，
//      粘贴进富文本编辑器造成存储型 XSS；
//   3. 禁止复制滥用：页面一律 preventDefault 阻断 copy/cut/selectstart，剥夺用户
//      复制权（反盗版过度），浏览器应允许用户“强制复制真实选区”；
//   4. 跨框架读取选区：子框架把父框架/跨源选区内容读走。
//
// 本模块裁决“页面是否有权替换剪贴板、替换内容是否安全、是否应放行真实选区、
// 跨框能否读取选区”，纯函数，不触碰 document/navigator。

const SEL_ALLOW = 'allow';
const SEL_DENY = 'deny';
const SEL_FORCE_REAL = 'force-real-selection'; // 忽略页面覆盖，写入用户真实选区

const SEL_REASON = Object.freeze({
  INSECURE_CONTEXT: 'sel-insecure-context',
  BAD_ORIGIN: 'sel-bad-origin',
  NO_GESTURE: 'sel-no-user-gesture',
  UNTRUSTED_FRAME: 'sel-untrusted-frame',
  OVERRIDE_MISMATCH: 'sel-override-differs-from-selection',
  DANGEROUS_URL: 'sel-clipboard-dangerous-url',
  DANGEROUS_HTML: 'sel-clipboard-dangerous-html',
  PAYLOAD_TOO_LARGE: 'sel-payload-too-large',
  COPY_BLOCKED_ABUSE: 'sel-copy-prevented-abusively',
  CROSS_FRAME_READ: 'sel-cross-frame-selection-read',
});

function defaultSelectionPolicy() {
  return {
    requireSecureContext: true,
    requireUserGesture: true,
    allowCrossFrameRead: false,
    allowIframes: false,
    maxPlainBytes: 1 << 20, // 1 MiB
    // 允许覆盖文本与真实选区存在差异的场景（如引用来源小尾巴），但危险内容仍拒。
    allowBenignAttribution: true,
  };
}

function originKey(origin) {
  if (typeof origin !== 'string') return '';
  const idx = origin.indexOf('://');
  if (idx <= 0) return '';
  const scheme = origin.slice(0, idx).toLowerCase();
  if (scheme !== 'https' && scheme !== 'http') return '';
  const rest = origin.slice(idx + 3);
  if (rest === '' || rest.includes('/') || rest.includes('?') || rest.includes('#')) return '';
  return scheme + '://' + rest.toLowerCase();
}

const DANGEROUS_URL_SCHEMES = [
  'javascript:', 'data:', 'vbscript:', 'file:', 'jar:', 'view-source:',
];

// findScheme 返回字符串（去前导空白与控制符后）开头的危险 scheme（小写），无则空。
// 纯字符匹配，不用正则。
function leadingDangerousScheme(text) {
  if (typeof text !== 'string') return '';
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || c === 32) { i++; continue; }
    break;
  }
  const head = text.slice(i).toLowerCase();
  for (const sch of DANGEROUS_URL_SCHEMES) {
    if (head.startsWith(sch)) return sch;
  }
  return '';
}

// scanTextForDangerousURL 在整段文本里查找危险 scheme（剪贴板可能是多行命令）。
// 识别行首出现的 javascript:/vbscript:（复制到终端/地址栏风险最高），以及
// data:text/html。纯字符扫描。
function textContainsDangerousURL(text) {
  if (typeof text !== 'string') return '';
  const lower = text.toLowerCase();
  // 整体开头
  const lead = leadingDangerousScheme(text);
  if (lead === 'javascript:' || lead === 'vbscript:') return lead;
  // 任意行首
  let from = 0;
  while (true) {
    const nl = lower.indexOf('\n', from);
    const seg = nl < 0 ? lower.slice(from) : lower.slice(from, nl);
    const s = leadingDangerousScheme(seg);
    if (s === 'javascript:' || s === 'vbscript:') return s;
    if (nl < 0) break;
    from = nl + 1;
  }
  if (lower.includes('data:text/html')) return 'data:text/html';
  return '';
}

// htmlHasDangerousContent 检查 text/html 剪贴板片段是否含可执行内容。
// 纯字符小写包含匹配（保守，宁可误拦富文本也不放行脚本）。
function htmlHasDangerousContent(html) {
  if (typeof html !== 'string' || html === '') return '';
  const h = html.toLowerCase();
  const needles = [
    '<script', 'javascript:', '<iframe', '<object', '<embed',
    'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onbegin',
    '<form', '<meta http-equiv', 'srcdoc', 'data:text/html',
  ];
  for (const n of needles) {
    if (h.includes(n)) return n;
  }
  return '';
}

function byteLen(s) {
  if (typeof s !== 'string') return 0;
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    n += c < 0x80 ? 1 : (c < 0x800 ? 2 : 3);
  }
  return n;
}

class SelectionGuard {
  constructor(policy) {
    this.policy = policy || defaultSelectionPolicy();
  }

  _baseDenied(ctx) {
    const pol = this.policy;
    if (!ctx || typeof ctx !== 'object') return SEL_REASON.BAD_ORIGIN;
    if (pol.requireSecureContext && !ctx.isSecureContext) return SEL_REASON.INSECURE_CONTEXT;
    if (!originKey(ctx.origin)) return SEL_REASON.BAD_ORIGIN;
    if (pol.requireUserGesture && ctx.hasUserGesture !== true) return SEL_REASON.NO_GESTURE;
    if (!pol.allowIframes && ctx.isTopFrame === false) return SEL_REASON.UNTRUSTED_FRAME;
    return '';
  }

  // evaluateClipboardOverride 裁决页面在 copy/cut 中要写入剪贴板的内容。
  // input: { context:{origin,isSecureContext,hasUserGesture,isTopFrame},
  //          selectedText(用户真实选区), overrideText, overrideHtml }
  // 返回 { decision, reason, text, html }。
  evaluateClipboardOverride(input) {
    const pol = this.policy;
    const base = this._baseDenied(input && input.context);
    if (base) return { decision: SEL_DENY, reason: base, text: '', html: '' };

    const text = typeof input.overrideText === 'string' ? input.overrideText : '';
    const html = typeof input.overrideHtml === 'string' ? input.overrideHtml : '';
    if (byteLen(text) > pol.maxPlainBytes || byteLen(html) > pol.maxPlainBytes) {
      return { decision: SEL_DENY, reason: SEL_REASON.PAYLOAD_TOO_LARGE, text: '', html: '' };
    }
    if (textContainsDangerousURL(text)) {
      return { decision: SEL_DENY, reason: SEL_REASON.DANGEROUS_URL, text: '', html: '' };
    }
    if (htmlHasDangerousContent(html)) {
      return { decision: SEL_DENY, reason: SEL_REASON.DANGEROUS_HTML, text: '', html: '' };
    }

    const selected = typeof input.selectedText === 'string' ? input.selectedText : '';
    const differs = text !== '' && selected !== '' && text !== selected;
    if (differs && !pol.allowBenignAttribution) {
      // 覆盖内容与真实选区不一致：不放行覆盖，回落到真实选区。
      return {
        decision: SEL_FORCE_REAL, reason: SEL_REASON.OVERRIDE_MISMATCH,
        text: selected, html: '',
      };
    }
    return { decision: SEL_ALLOW, reason: differs ? '' : '', text, html };
  }

  // onCopyPrevented 裁决页面对 copy 事件 preventDefault 的处理。
  // hasSelection=true 表示用户确实选中了可复制内容却被拦，按“禁止复制滥用”
  // 返回 force-real（由注入层把真实选区写进剪贴板）。
  onCopyPrevented(ctx, hasSelection) {
    const base = this._baseDenied(ctx);
    if (base) return { decision: SEL_DENY, reason: base };
    if (hasSelection === true) {
      return { decision: SEL_FORCE_REAL, reason: SEL_REASON.COPY_BLOCKED_ABUSE };
    }
    return { decision: SEL_ALLOW, reason: '' };
  }

  // canReadSelection 裁决跨框架/跨源读取选区。
  canReadSelection(ctx, targetIsSameOrigin) {
    const base = this._baseDenied(ctx);
    if (base) return { allowed: false, reason: base };
    if (targetIsSameOrigin !== true && !this.policy.allowCrossFrameRead) {
      return { allowed: false, reason: SEL_REASON.CROSS_FRAME_READ };
    }
    return { allowed: true, reason: '' };
  }
}

// sanitizePlainForClipboard 去掉可执行 scheme 行，返回安全纯文本（纵深防御）。
function sanitizePlainForClipboard(text) {
  if (typeof text !== 'string') return '';
  const lines = text.split('\n');
  const kept = lines.filter((ln) => {
    const s = leadingDangerousScheme(ln);
    return s !== 'javascript:' && s !== 'vbscript:';
  });
  return kept.join('\n');
}

module.exports = {
  SEL_ALLOW, SEL_DENY, SEL_FORCE_REAL, SEL_REASON,
  defaultSelectionPolicy, originKey, SelectionGuard,
  leadingDangerousScheme, textContainsDangerousURL,
  htmlHasDangerousContent, byteLen, sanitizePlainForClipboard,
};
