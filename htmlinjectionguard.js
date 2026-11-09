'use strict';
const { describeReasonFrom } = require('./reasontext');

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
  return describeReasonFrom({
    [REASON.EMPTY]: '待注入文本为空或不是字符串',
    [REASON.TOO_LARGE]: '待注入文本超过长度上限',
    [REASON.NUL_BYTE]: '待注入文本含空字节',
    [REASON.SCRIPT_TAG]: '待注入文本含 script 标签',
    [REASON.IFRAME_TAG]: '待注入文本含 iframe 标签',
    [REASON.SVG_TAG]: '待注入文本含 svg 标签',
    [REASON.EVENT_HANDLER]: '待注入文本含事件处理属性',
    [REASON.JAVASCRIPT_URI]: '待注入文本含脚本伪协议',
    [REASON.DATA_HTML]: '待注入文本含 data:text/html 地址',
    [REASON.STYLE_EXPRESSION]: '待注入文本含样式表达式',
  }, reason, '待注入文本不含标签');
}

module.exports = {
  REASON,
  MAX_CHARS,
  inspectText,
  applyHtmlInjectionGuard,
  describeReason,
};
