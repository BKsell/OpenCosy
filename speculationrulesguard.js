'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  MULTIPLE: 'multiple-sources',
  INSECURE: 'insecure-source',
  CREDENTIALS: 'source-credentials',
  PATH_SHAPE: 'source-path-shape',
  CROSS_ORIGIN: 'cross-origin-source',
};

const HEADER = 'speculation-rules';
const MAX_VALUE_LENGTH = 512;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function unquote(text) {
  const value = text.trim();
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    return value.slice(1, -1).trim();
  }
  return value;
}

function originOf(value) {
  try {
    return new URL(value).origin;
  } catch (err) {
    return '';
  }
}

function inspectSpeculationRules(value, docOrigin) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, items: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, items: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, items: [] };
  if (/^http:\/\//i.test(text) || /^(file|data|javascript|blob):/i.test(text)) {
    return { reason: REASON.INSECURE, items: [] };
  }
  if (text.includes(',')) return { reason: REASON.MULTIPLE, items: [] };

  const target = unquote(text);
  if (!target) return { reason: REASON.MALFORMED, items: [] };
  if (target.includes('@')) return { reason: REASON.CREDENTIALS, items: [] };
  if (/^http:\/\//i.test(target) || /^(file|data|javascript|blob):/i.test(target)) {
    return { reason: REASON.INSECURE, items: [] };
  }
  if (target.includes('..') || target.includes('\\')) {
    return { reason: REASON.PATH_SHAPE, items: [] };
  }
  const base = originOf(docOrigin) || docOrigin;
  const targetOrigin = originOf(target);
  if (base && targetOrigin && targetOrigin !== base) {
    return { reason: REASON.CROSS_ORIGIN, items: [] };
  }
  return { reason: REASON.OK, items: [target] };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'speculation-rules 合规';
    case REASON.MISSING:
      return '响应未声明 speculation-rules';
    case REASON.MALFORMED:
      return 'speculation-rules 取值非法';
    case REASON.OVERLONG:
      return 'speculation-rules 超长';
    case REASON.MULTIPLE:
      return 'speculation-rules 声明了多个来源，已剥除';
    case REASON.INSECURE:
      return 'speculation-rules 指向明文或本地资源，已剥除';
    case REASON.CREDENTIALS:
      return 'speculation-rules 来源内嵌凭据，已剥除';
    case REASON.PATH_SHAPE:
      return 'speculation-rules 来源包含路径穿越片段，已剥除';
    case REASON.CROSS_ORIGIN:
      return 'speculation-rules 来源跨源，已剥除';
    default:
      return 'speculation-rules 未识别状态';
  }
}

function applySpeculationRulesGuard(headers, docOrigin) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, items: [] };
  const result = inspectSpeculationRules(value, docOrigin);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, items: result.items };
  }
  deleteHeader(headers, HEADER);
  return { changed: true, reason: result.reason, items: [] };
}

module.exports = {
  REASON,
  HEADER,
  inspectSpeculationRules,
  applySpeculationRulesGuard,
  describeReason,
};
