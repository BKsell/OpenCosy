'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  TOO_LARGE: 'too-large',
  NUL_BYTE: 'nul-byte',
  SCRIPT_TAG: 'script-tag',
  IFRAME_TAG: 'iframe-tag',
  SVG_TAG: 'svg-tag',
  EVENT_HANDLER: 'event-handler',
  JAVASCRIPT_URI: 'javascript-uri',
  DATA_HTML: 'data-html-uri',
  STYLE_EXPRESSION: 'style-expression',
};

const MAX_CHARS = 8192;
const EVENT_PATTERN = /\son[a-z]{3,24}\s*=/i;
const JS_URI_PATTERN = /(?:javascript|vbscript)\s*:/i;
const DATA_HTML_PATTERN = /data\s*:\s*text\/html/i;
const STYLE_EXPRESSION_PATTERN = /expression\s*\(|@import/i;

function inspectText(value, options) {
  const opts = options || {};
  const allowMarkup = opts.allowMarkup === true;
  if (typeof value !== 'string') return { ok: false, reason: REASON.EMPTY, matches: [] };
  if (!value) return { ok: false, reason: REASON.EMPTY, matches: [] };
  if (value.length > MAX_CHARS) return { ok: false, reason: REASON.TOO_LARGE, matches: [] };
  if (value.includes('\u0000')) return { ok: false, reason: REASON.NUL_BYTE, matches: [] };
  if (allowMarkup) return { ok: true, reason: REASON.OK, matches: [] };
  const lower = value.toLowerCase();
  const matches = [];
  if (lower.includes('<script')) matches.push(REASON.SCRIPT_TAG);
  if (lower.includes('<iframe')) matches.push(REASON.IFRAME_TAG);
  if (lower.includes('<svg')) matches.push(REASON.SVG_TAG);
  if (EVENT_PATTERN.test(value)) matches.push(REASON.EVENT_HANDLER);
  if (JS_URI_PATTERN.test(value)) matches.push(REASON.JAVASCRIPT_URI);
  if (DATA_HTML_PATTERN.test(value)) matches.push(REASON.DATA_HTML);
  if (STYLE_EXPRESSION_PATTERN.test(value)) matches.push(REASON.STYLE_EXPRESSION);
  if (matches.length === 0) return { ok: true, reason: REASON.OK, matches: [] };
  return { ok: false, reason: matches[0], matches };
}

function applyHtmlInjectionGuard(value, options) {
  const result = inspectText(value, options);
  return { changed: !result.ok, reason: result.reason, matches: result.matches };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return '待注入文本为空或不是字符串';
    case REASON.TOO_LARGE:
      return '待注入文本超过长度上限';
    case REASON.NUL_BYTE:
      return '待注入文本含空字节';
    case REASON.SCRIPT_TAG:
      return '待注入文本含 script 标签';
    case REASON.IFRAME_TAG:
      return '待注入文本含 iframe 标签';
    case REASON.SVG_TAG:
      return '待注入文本含 svg 标签';
    case REASON.EVENT_HANDLER:
      return '待注入文本含事件处理属性';
    case REASON.JAVASCRIPT_URI:
      return '待注入文本含脚本伪协议';
    case REASON.DATA_HTML:
      return '待注入文本含 data:text/html 地址';
    case REASON.STYLE_EXPRESSION:
      return '待注入文本含样式表达式';
    default:
      return '待注入文本不含标签';
  }
}

module.exports = {
  REASON,
  MAX_CHARS,
  inspectText,
  applyHtmlInjectionGuard,
  describeReason,
};
