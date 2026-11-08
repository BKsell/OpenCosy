'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty',
  MALFORMED: 'malformed',
  WILDCARD: 'wildcard-type',
  BAD_CHARSET: 'bad-charset',
  DUPLICATE_PARAM: 'duplicate-parameter',
  HTML_DISALLOWED: 'html-disallowed',
  SNIFFABLE: 'sniffable',
};

const TOKEN = /^[a-z0-9!#$&^_.+-]{1,64}$/;
const TEXT_TYPES = new Set(['text/plain', 'text/csv', 'text/html', 'text/css', 'text/javascript', 'text/markdown']);
const SNIFFABLE_TYPES = new Set(['text/plain', 'application/octet-stream']);

function inspectContentType(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || !value.trim()) return { ok: false, reason: REASON.EMPTY };
  if (value.length > 256) return { ok: false, reason: REASON.MALFORMED };
  const pieces = value.split(';');
  const essence = pieces[0].trim().toLowerCase();
  const slash = essence.indexOf('/');
  if (slash <= 0 || slash === essence.length - 1) return { ok: false, reason: REASON.MALFORMED };
  const type = essence.slice(0, slash);
  const subtype = essence.slice(slash + 1);
  if (type === '*' || subtype === '*') return { ok: false, reason: REASON.WILDCARD };
  if (!TOKEN.test(type) || !TOKEN.test(subtype)) return { ok: false, reason: REASON.MALFORMED };
  const params = new Map();
  let duplicate = false;
  for (let i = 1; i < pieces.length; i += 1) {
    const param = pieces[i].trim();
    if (!param) continue;
    const eq = param.indexOf('=');
    if (eq <= 0) return { ok: false, reason: REASON.MALFORMED };
    const name = param.slice(0, eq).trim().toLowerCase();
    const raw = param.slice(eq + 1).trim().replace(/^"|"$/g, '');
    if (params.has(name)) duplicate = true;
    params.set(name, raw);
  }
  if (duplicate) return { ok: false, reason: REASON.DUPLICATE_PARAM };
  const charset = params.get('charset');
  if (charset) {
    const lower = charset.toLowerCase();
    if (lower !== 'utf-8' && lower !== 'us-ascii') return { ok: false, reason: REASON.BAD_CHARSET };
  }
  if (essence === 'text/html' && opts.allowHtml === false) return { ok: false, reason: REASON.HTML_DISALLOWED };
  if (opts.download === true && SNIFFABLE_TYPES.has(essence)) return { ok: false, reason: REASON.SNIFFABLE };
  return { ok: true, reason: REASON.OK, essence, charset: charset || 'utf-8', isText: TEXT_TYPES.has(essence) };
}

function applyMimeTypePolicyGuard(value, options) {
  const result = inspectContentType(value, options);
  return { changed: !result.ok, reason: result.reason, essence: result.essence || '' };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.EMPTY:
      return 'Content-Type 为空';
    case REASON.MALFORMED:
      return 'Content-Type 格式非法';
    case REASON.WILDCARD:
      return 'Content-Type 使用通配类型';
    case REASON.BAD_CHARSET:
      return '文本类型使用非 UTF-8 字符集';
    case REASON.DUPLICATE_PARAM:
      return 'Content-Type 参数重复';
    case REASON.HTML_DISALLOWED:
      return '当前上下文不允许 HTML 类型';
    case REASON.SNIFFABLE:
      return '下载响应使用易被嗅探的通用类型';
    default:
      return 'Content-Type 合法';
  }
}

module.exports = {
  REASON,
  TEXT_TYPES,
  SNIFFABLE_TYPES,
  inspectContentType,
  applyMimeTypePolicyGuard,
  describeReason,
};
