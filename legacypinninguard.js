'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  DEPRECATED: 'deprecated',
  MALFORMED: 'malformed',
  UNSAFE_PIN: 'unsafe-pin',
};

const MAX_VALUE_LENGTH = 1024;

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

function pinLooksUnsafe(value) {
  if (!value) return false;
  if (!/pin-sha256=/i.test(value)) return false;
  if (!/max-age=/i.test(value)) return true;
  return false;
}

function inspectLegacyPinHeaders(headers) {
  const findings = [];
  const names = ['expect-ct', 'public-key-pins', 'public-key-pins-report-only'];
  for (const name of names) {
    const value = firstValue(headers, name);
    if (!value) continue;
    if (value.length > MAX_VALUE_LENGTH) {
      findings.push({ header: name, reason: REASON.MALFORMED });
      continue;
    }
    if (name !== 'expect-ct' && pinLooksUnsafe(value)) {
      findings.push({ header: name, reason: REASON.UNSAFE_PIN });
      continue;
    }
    findings.push({ header: name, reason: REASON.DEPRECATED });
  }
  if (!findings.length) {
    return { changed: false, reason: REASON.MISSING, findings };
  }
  const reason = findings.some((item) => item.reason === REASON.MALFORMED)
    ? REASON.MALFORMED
    : findings.some((item) => item.reason === REASON.UNSAFE_PIN)
      ? REASON.UNSAFE_PIN
      : REASON.DEPRECATED;
  return { changed: true, reason, findings };
}

function applyLegacyPinninguard(headers) {
  const result = inspectLegacyPinHeaders(headers);
  if (!result.changed) return result;
  for (const name of ['expect-ct', 'public-key-pins', 'public-key-pins-report-only']) {
    const key = headerKey(headers, name);
    if (key) delete headers[key];
  }
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.DEPRECATED:
      return '命中已废弃的安全头（Expect-CT / HPKP）';
    case REASON.MALFORMED:
      return '废弃安全头取值过长';
    case REASON.UNSAFE_PIN:
      return 'HPKP 固定策略缺少 max-age 或格式异常';
    case REASON.MISSING:
      return '未声明废弃安全头';
    default:
      return '未发现废弃安全头';
  }
}

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  pinLooksUnsafe,
  inspectLegacyPinHeaders,
  applyLegacyPinninguard,
  describeReason,
};
