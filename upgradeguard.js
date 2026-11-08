'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  INSECURE_PROTOCOL: 'insecure-protocol',
  UNKNOWN_PROTOCOL: 'unknown-protocol',
  WITHOUT_CONNECTION: 'missing-connection-upgrade',
};

const HEADER = 'upgrade';
const CONNECTION_HEADER = 'connection';
const MAX_VALUE_LENGTH = 256;
const SAFE_PROTOCOLS = new Set(['websocket']);

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

function hasConnectionUpgrade(headers) {
  const value = firstValue(headers, CONNECTION_HEADER).toLowerCase();
  if (!value) return false;
  return value.split(',').some((token) => token.trim() === 'upgrade');
}

function inspectUpgrade(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, protocols: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, protocols: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, protocols: [] };

  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of text.split(',')) {
    const token = raw.trim().toLowerCase();
    if (!token) continue;
    if (token === 'h2c' || token === 'http/1.0' || token === 'tls/1.0' || token === 'http/1.1') {
      note(REASON.INSECURE_PROTOCOL);
      continue;
    }
    if (!SAFE_PROTOCOLS.has(token)) {
      note(REASON.UNKNOWN_PROTOCOL);
      continue;
    }
    if (seen.has(token)) continue;
    seen.add(token);
    kept.push(token);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, protocols: [] };
  return { reason, protocols: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'upgrade 协议合规';
    case REASON.MISSING:
      return '响应未声明 upgrade';
    case REASON.MALFORMED:
      return 'upgrade 取值非法';
    case REASON.OVERLONG:
      return 'upgrade 超长';
    case REASON.INSECURE_PROTOCOL:
      return 'upgrade 声明明文或旧式协议，已剔除';
    case REASON.UNKNOWN_PROTOCOL:
      return 'upgrade 协议不在白名单，已剔除';
    case REASON.WITHOUT_CONNECTION:
      return 'upgrade 缺少 connection: upgrade 配对，已剥除';
    default:
      return 'upgrade 未识别状态';
  }
}

function applyUpgradeHeaderGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, protocols: [] };
  const result = inspectUpgrade(value);
  if (result.reason === REASON.OK && !hasConnectionUpgrade(headers)) {
    deleteHeader(headers, HEADER);
    return { changed: true, reason: REASON.WITHOUT_CONNECTION, protocols: [] };
  }
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, protocols: result.protocols };
  }
  if (result.protocols.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.protocols.join(', ')];
  }
  return { changed: true, reason: result.reason, protocols: result.protocols };
}

module.exports = {
  REASON,
  HEADER,
  inspectUpgrade,
  applyUpgradeHeaderGuard,
  describeReason,
};
