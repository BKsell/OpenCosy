'use strict';
const { describeReasonFrom } = require('./reasontext');

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  TOO_LARGE: 'too-large',
  SCRIPT_TAG: 'script-tag',
  EVENT_HANDLER: 'event-handler',
  FOREIGN_OBJECT: 'foreign-object',
  JAVASCRIPT_URI: 'javascript-uri',
  IFRAME_EMBED: 'iframe-or-embed',
  ENTITY_DECL: 'entity-declaration',
  EXTERNAL_DTD: 'external-dtd',
};

const MAX_BYTES = 512 * 1024;
const EVENT_PATTERN = /\son[a-z]{3,20}\s*=/i;
const JS_URI_PATTERN = /(?:href|xlink:href|src)\s*=\s*["']?\s*(?:javascript|vbscript|data:text\/html)[:;,]/i;

function inspectSvg(content) {
  if (typeof content !== 'string') return { ok: false, reason: REASON.EMPTY, matches: [] };
  if (!content.trim()) return { ok: false, reason: REASON.EMPTY, matches: [] };
  if (Buffer.byteLength(content, 'utf8') > MAX_BYTES) return { ok: false, reason: REASON.TOO_LARGE, matches: [] };
  const lower = content.toLowerCase();
  const matches = [];
  if (lower.includes('<script')) matches.push('script');
  if (EVENT_PATTERN.test(content)) matches.push('event-handler');
  if (lower.includes('<foreignobject')) matches.push('foreign-object');
  if (JS_URI_PATTERN.test(content)) matches.push('javascript-uri');
  if (lower.includes('<iframe') || lower.includes('<embed')) matches.push('iframe-embed');
  if (lower.includes('<!entity')) matches.push('entity');
  if (lower.includes('<!doctype') && lower.includes('system')) matches.push('external-dtd');
  if (matches.length === 0) return { ok: true, reason: REASON.OK, matches: [] };
  const map = {
    script: REASON.SCRIPT_TAG,
    'event-handler': REASON.EVENT_HANDLER,
    'foreign-object': REASON.FOREIGN_OBJECT,
    'javascript-uri': REASON.JAVASCRIPT_URI,
    'iframe-embed': REASON.IFRAME_EMBED,
    entity: REASON.ENTITY_DECL,
    'external-dtd': REASON.EXTERNAL_DTD,
  };
  return { ok: false, reason: map[matches[0]] || REASON.SCRIPT_TAG, matches };
}

function applySvgScriptGuard(content) {
  const result = inspectSvg(content);
  return { changed: !result.ok, reason: result.reason, matches: result.matches };
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.EMPTY]: 'SVG 内容为空',
    [REASON.TOO_LARGE]: 'SVG 超过体积上限',
    [REASON.SCRIPT_TAG]: 'SVG 包含 script 标签',
    [REASON.EVENT_HANDLER]: 'SVG 包含事件处理属性',
    [REASON.FOREIGN_OBJECT]: 'SVG 包含 foreignObject 节点',
    [REASON.JAVASCRIPT_URI]: 'SVG 引用脚本伪协议地址',
    [REASON.IFRAME_EMBED]: 'SVG 包含 iframe 或 embed',
    [REASON.ENTITY_DECL]: 'SVG 包含实体声明',
    [REASON.EXTERNAL_DTD]: 'SVG 引用外部 DTD',
  }, reason, 'SVG 内容安全');
}

module.exports = {
  REASON,
  MAX_BYTES,
  inspectSvg,
  applySvgScriptGuard,
  describeReason,
};
