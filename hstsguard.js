'use strict';
const { describeReasonTable } = require('./reasontext');
const { applySingleHeaderGuard } = require('./guardapply');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  DISABLED: 'disabled',
  MALFORMED: 'malformed',
  DUPLICATE: 'duplicate',
};

const MAX_VALUE_LENGTH = 256;
const MIN_ACCEPTABLE_MAX_AGE = 86400;

function parseHsts(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.MALFORMED };
  const directives = text.split(';').map((part) => part.trim()).filter(Boolean);
  const seen = new Set();
  let maxAge = null;
  for (const directive of directives) {
    const eq = directive.indexOf('=');
    const name = (eq < 0 ? directive : directive.slice(0, eq)).trim().toLowerCase();
    if (seen.has(name)) return { reason: REASON.DUPLICATE };
    seen.add(name);
    if (name === 'max-age') {
      if (eq < 0) return { reason: REASON.MALFORMED };
      const raw = directive.slice(eq + 1).trim().replace(/^"|"$/g, '');
      if (!/^\d{1,16}$/.test(raw)) return { reason: REASON.MALFORMED };
      maxAge = Number(raw);
    }
  }
  if (maxAge === null) return { reason: REASON.MALFORMED };
  if (maxAge === 0) return { reason: REASON.DISABLED, maxAge };
  if (maxAge < MIN_ACCEPTABLE_MAX_AGE) return { reason: REASON.DISABLED, maxAge };
  return { reason: REASON.OK, maxAge, includeSubDomains: seen.has('includesubdomains') };
}

function inspectHsts(headers) {
  const value = firstValue(headers, 'strict-transport-security');
  if (!value) return { changed: false, reason: REASON.MISSING, verdict: null };
  const parsed = parseHsts(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, verdict: parsed };
  }
  return { changed: true, reason: parsed.reason, verdict: parsed };
}

function applyHstsGuard(headers) {
  return applySingleHeaderGuard(headers, 'strict-transport-security', inspectHsts);
}

const describeReason = describeReasonTable({
    [REASON.DISABLED]: '站点 HSTS 有效期过短或等于 0',
    [REASON.MALFORMED]: 'HSTS 头格式非法或缺 max-age',
    [REASON.DUPLICATE]: 'HSTS 头重复声明同一指令',
    [REASON.MISSING]: '站点未声明 HSTS',
  }, 'HSTS 策略有效');

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  MIN_ACCEPTABLE_MAX_AGE,
  parseHsts,
  inspectHsts,
  applyHstsGuard,
  describeReason,
};
