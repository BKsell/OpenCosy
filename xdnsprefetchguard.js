'use strict';
const { describeReasonTable } = require('./reasontext');

const { countValues, firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  MULTI_VALUE: 'multi-value',
  ENABLED: 'prefetch-enabled',
};

const HEADER = 'x-dns-prefetch-control';
const ALLOW = 'off';
const MAX_VALUE_LENGTH = 16;

function parseDnsPrefetch(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, enabled: null };
  const text = value.trim().toLowerCase();
  if (!text) return { reason: REASON.MALFORMED, enabled: null };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, enabled: null };
  if (text === 'off') return { reason: REASON.OK, enabled: false };
  if (text === 'on') return { reason: REASON.ENABLED, enabled: true };
  return { reason: REASON.MALFORMED, enabled: null };
}

function inspectDnsPrefetch(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, enabled: null };
  if (countValues(headers, HEADER) > 1) {
    return { changed: true, reason: REASON.MULTI_VALUE, enabled: null };
  }
  const parsed = parseDnsPrefetch(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, enabled: false };
  }
  return { changed: true, reason: parsed.reason, enabled: parsed.enabled };
}

function applyDnsPrefetchGuard(headers) {
  const result = inspectDnsPrefetch(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) headers[key] = ALLOW;
  return result;
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: 'X-DNS-Prefetch-Control 取值非法，已关闭预取',
    [REASON.OVERLONG]: 'X-DNS-Prefetch-Control 字段超长，已关闭预取',
    [REASON.MULTI_VALUE]: 'X-DNS-Prefetch-Control 重复下发，已收敛为单值',
    [REASON.ENABLED]: '页面开启 DNS 预取，已关闭以收敛跨域探测',
    [REASON.MISSING]: '响应未声明 X-DNS-Prefetch-Control',
  }, 'X-DNS-Prefetch-Control 已关闭');

module.exports = {
  REASON,
  HEADER,
  ALLOW,
  MAX_VALUE_LENGTH,
  headerKey,
  firstValue,
  countValues,
  parseDnsPrefetch,
  inspectDnsPrefetch,
  applyDnsPrefetchGuard,
  describeReason,
};
