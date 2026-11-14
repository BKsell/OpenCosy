'use strict';
const { describeReasonTable } = require('./reasontext');
const { applyDeprecatedHeaderGuard } = require('./guardapply_core');

require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  DEPRECATED: 'deprecated-pinning',
  NO_BACKUP_PIN: 'missing-backup-pin',
  UNSAFE_MAX_AGE: 'unsafe-max-age',
  REPORT_URI: 'report-uri-present',
};

const HEADER = 'public-key-pins';
const MAX_VALUE_LENGTH = 1024;
const MAX_MAX_AGE = 2592000;

function inspectPublicKeyPins(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, pins: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, pins: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, pins: [] };

  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };
  const pins = [];
  let maxAge = null;
  const parts = [];
  let current = '';
  let inQuote = false;
  for (const ch of text) {
    if (ch === '"') inQuote = !inQuote;
    if ((ch === ',' || ch === ';') && !inQuote) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current) parts.push(current);
  for (const raw of parts) {
    const piece = raw.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    const name = (eq >= 0 ? piece.slice(0, eq) : piece).trim().toLowerCase();
    const captured = eq >= 0 ? piece.slice(eq + 1).replace(/"/g, '').trim() : '';
    if (name === 'max-age') {
      const seconds = Number(captured);
      if (!Number.isInteger(seconds) || seconds < 0) {
        note(REASON.MALFORMED);
        continue;
      }
      maxAge = seconds;
      continue;
    }
    if (name === 'include-subdomains' || name === 'report-only') continue;
    if (name === 'report-uri') {
      note(REASON.REPORT_URI);
      continue;
    }
    if (name === 'pin-sha256') {
      if (!captured) {
        note(REASON.MALFORMED);
        continue;
      }
      pins.push(captured);
      continue;
    }
    note(REASON.MALFORMED);
  }
  if (maxAge !== null && maxAge > MAX_MAX_AGE) note(REASON.UNSAFE_MAX_AGE);
  if (pins.length > 0 && pins.length < 2) note(REASON.NO_BACKUP_PIN);
  return { reason, pins, maxAge };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'public-key-pins 取值合规但该响应头已废弃',
    [REASON.MISSING]: '响应未声明 public-key-pins',
    [REASON.MALFORMED]: 'public-key-pins 指令非法',
    [REASON.OVERLONG]: 'public-key-pins 超长',
    [REASON.DEPRECATED]: 'public-key-pins 已废弃且可致站点锁死，整头剥除',
    [REASON.NO_BACKUP_PIN]: 'public-key-pins 缺少备份钉，存在锁站风险',
    [REASON.UNSAFE_MAX_AGE]: 'public-key-pins 缓存时长超出上限',
    [REASON.REPORT_URI]: 'public-key-pins 携带上报地址',
  }, 'public-key-pins 未识别状态');

function applyPublicKeyPinsGuard(headers) {
  return applyDeprecatedHeaderGuard(headers, HEADER, inspectPublicKeyPins, { reason: REASON.DEPRECATED, missingReason: REASON.MISSING, field: 'pins' });
}

module.exports = {
  REASON,
  HEADER,
  inspectPublicKeyPins,
  applyPublicKeyPinsGuard,
  describeReason,
};
