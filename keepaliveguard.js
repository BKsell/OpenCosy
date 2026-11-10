'use strict';
const { describeReasonTable } = require('./reasontext');
const { applySingleHeaderGuard } = require('./guardapply');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  TIMEOUT_RANGE: 'timeout-range',
  MAX_RANGE: 'max-range',
  DUPLICATE_PARAM: 'duplicate-param',
};

const HEADER = 'keep-alive';
const MAX_VALUE_LENGTH = 96;
const MAX_TIMEOUT = 300;
const MAX_REQUESTS = 1000;

function parseKeepAlive(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, timeout: null, max: null };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, timeout: null, max: null };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, timeout: null, max: null };
  const params = text.split(/[;,]/, -1).map((entry) => entry.trim()).filter((entry) => entry !== '');
  if (params.length === 0 || params.length > 3) {
    return { reason: REASON.MALFORMED, timeout: null, max: null };
  }
  const seen = new Map();
  for (const param of params) {
    const eq = param.indexOf('=');
    if (eq <= 0) return { reason: REASON.MALFORMED, timeout: null, max: null };
    const key = param.slice(0, eq).trim().toLowerCase();
    const raw = param.slice(eq + 1).trim();
    if (key !== 'timeout' && key !== 'max') {
      return { reason: REASON.MALFORMED, timeout: null, max: null };
    }
    if (seen.has(key)) return { reason: REASON.DUPLICATE_PARAM, timeout: null, max: null };
    if (!/^\d{1,10}$/.test(raw)) return { reason: REASON.MALFORMED, timeout: null, max: null };
    seen.set(key, Number(raw));
  }
  const timeout = seen.has('timeout') ? seen.get('timeout') : null;
  const max = seen.has('max') ? seen.get('max') : null;
  if (timeout !== null && timeout > MAX_TIMEOUT) {
    return { reason: REASON.TIMEOUT_RANGE, timeout, max };
  }
  if (max !== null && max > MAX_REQUESTS) {
    return { reason: REASON.MAX_RANGE, timeout, max };
  }
  return { reason: REASON.OK, timeout, max };
}

function inspectKeepAlive(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, timeout: null, max: null };
  const parsed = parseKeepAlive(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, timeout: parsed.timeout, max: parsed.max };
  }
  return { changed: true, reason: parsed.reason, timeout: parsed.timeout, max: parsed.max };
}

function applyKeepAliveGuard(headers) {
  return applySingleHeaderGuard(headers, HEADER, inspectKeepAlive);
}

const describeReason = describeReasonTable({
    [REASON.MALFORMED]: 'Keep-Alive 参数语法非法',
    [REASON.OVERLONG]: 'Keep-Alive 字段超长',
    [REASON.TIMEOUT_RANGE]: 'Keep-Alive 超时时间超出预算',
    [REASON.MAX_RANGE]: 'Keep-Alive 请求上限超出预算',
    [REASON.DUPLICATE_PARAM]: 'Keep-Alive 参数重复声明',
  }, 'Keep-Alive 参数通过校验');

module.exports = {
  REASON,
  HEADER,
  MAX_VALUE_LENGTH,
  MAX_TIMEOUT,
  MAX_REQUESTS,
  headerKey,
  firstValue,
  parseKeepAlive,
  inspectKeepAlive,
  applyKeepAliveGuard,
  describeReason,
};
