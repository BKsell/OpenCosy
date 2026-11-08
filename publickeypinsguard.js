'use strict';

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

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'public-key-pins 取值合规但该响应头已废弃';
    case REASON.MISSING:
      return '响应未声明 public-key-pins';
    case REASON.MALFORMED:
      return 'public-key-pins 指令非法';
    case REASON.OVERLONG:
      return 'public-key-pins 超长';
    case REASON.DEPRECATED:
      return 'public-key-pins 已废弃且可致站点锁死，整头剥除';
    case REASON.NO_BACKUP_PIN:
      return 'public-key-pins 缺少备份钉，存在锁站风险';
    case REASON.UNSAFE_MAX_AGE:
      return 'public-key-pins 缓存时长超出上限';
    case REASON.REPORT_URI:
      return 'public-key-pins 携带上报地址';
    default:
      return 'public-key-pins 未识别状态';
  }
}

function applyPublicKeyPinsGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, pins: [] };
  const result = inspectPublicKeyPins(value);
  deleteHeader(headers, HEADER);
  return { changed: true, reason: REASON.DEPRECATED, pins: result.pins };
}

module.exports = {
  REASON,
  HEADER,
  inspectPublicKeyPins,
  applyPublicKeyPinsGuard,
  describeReason,
};
