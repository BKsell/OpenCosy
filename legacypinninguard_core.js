'use strict';
const { describeReasonTable } = require('./reasontext');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  DEPRECATED: 'deprecated',
  MALFORMED: 'malformed',
  UNSAFE_PIN: 'unsafe-pin',
};

const MAX_VALUE_LENGTH = 1024;

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

const describeReason = describeReasonTable({
    [REASON.DEPRECATED]: '命中已废弃的安全头（Expect-CT / HPKP）',
    [REASON.MALFORMED]: '废弃安全头取值过长',
    [REASON.UNSAFE_PIN]: 'HPKP 固定策略缺少 max-age 或格式异常',
    [REASON.MISSING]: '未声明废弃安全头',
  }, '未发现废弃安全头');

module.exports = {
  REASON,
  MAX_VALUE_LENGTH,
  pinLooksUnsafe,
  inspectLegacyPinHeaders,
  applyLegacyPinninguard,
  describeReason,
};
