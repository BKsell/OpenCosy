'use strict';
const { describeReasonTable } = require('./reasontext');

const { deleteHeader, firstValue, headerKey } = require('./headerutil_core');

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

const describeReason = describeReasonTable({
    [REASON.OK]: 'speculation-rules 合规',
    [REASON.MISSING]: '响应未声明 speculation-rules',
    [REASON.MALFORMED]: 'speculation-rules 取值非法',
    [REASON.OVERLONG]: 'speculation-rules 超长',
    [REASON.MULTIPLE]: 'speculation-rules 声明了多个来源，已剥除',
    [REASON.INSECURE]: 'speculation-rules 指向明文或本地资源，已剥除',
    [REASON.CREDENTIALS]: 'speculation-rules 来源内嵌凭据，已剥除',
    [REASON.PATH_SHAPE]: 'speculation-rules 来源包含路径穿越片段，已剥除',
    [REASON.CROSS_ORIGIN]: 'speculation-rules 来源跨源，已剥除',
  }, 'speculation-rules 未识别状态');

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
