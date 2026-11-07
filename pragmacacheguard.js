'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_DIRECTIVE: 'bad-directive',
  MULTI_VALUE: 'multi-value',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 64;
const ALLOWED_DIRECTIVES = new Set(['no-cache']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function inspectPragma(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE };
  const token = text.toLowerCase();
  if (!ALLOWED_DIRECTIVES.has(token)) return { reason: REASON.BAD_DIRECTIVE, token };
  return { reason: REASON.OK, token };
}

function applyPragmaCacheGuard(headers) {
  const key = headerKey(headers, 'pragma');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectPragma(value);
  if (verdict.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, token: verdict.token };
  }
  delete headers[key];
  return { changed: true, reason: verdict.reason, token: verdict.token || null };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Pragma 仅保留 no-cache';
    case REASON.MISSING:
      return '未声明 Pragma';
    case REASON.BAD_DIRECTIVE:
      return 'Pragma 使用非标准缓存指令';
    case REASON.MULTI_VALUE:
      return 'Pragma 出现多个取值';
    case REASON.OVERLONG:
      return 'Pragma 取值超长';
    case REASON.MALFORMED:
      return 'Pragma 取值无法解析';
    default:
      return 'Pragma 未知状态';
  }
}

module.exports = {
  REASON,
  inspectPragma,
  applyPragmaCacheGuard,
  describeReason,
};
