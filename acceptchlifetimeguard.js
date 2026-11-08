'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OBSOLETE_HEADER: 'obsolete-header',
  BAD_RANGE: 'bad-range',
  MULTI_VALUE: 'multi-value',
  MALFORMED: 'malformed',
};

const MAX_LIFETIME = 31536000;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function inspectAcceptChLifetime(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.includes(',')) return { reason: REASON.MULTI_VALUE };
  if (!/^\d+$/.test(text)) return { reason: REASON.MALFORMED, value: text };
  const seconds = Number(text);
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > MAX_LIFETIME) {
    return { reason: REASON.BAD_RANGE, seconds };
  }
  return { reason: REASON.OBSOLETE_HEADER, seconds };
}

function applyAcceptChLifetimeGuard(headers) {
  const key = headerKey(headers, 'accept-ch-lifetime');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 3) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectAcceptChLifetime(value);
  delete headers[key];
  return {
    changed: true,
    reason: verdict.reason === REASON.MISSING ? REASON.MALFORMED : verdict.reason,
    seconds: verdict.seconds || null,
  };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'Accept-CH-Lifetime 状态正常';
    case REASON.MISSING:
      return '未声明 Accept-CH-Lifetime';
    case REASON.OBSOLETE_HEADER:
      return 'Accept-CH-Lifetime 已被规范退役，改用 Accept-CH 的持久化替代';
    case REASON.BAD_RANGE:
      return 'Accept-CH-Lifetime 有效期越界';
    case REASON.MULTI_VALUE:
      return 'Accept-CH-Lifetime 出现多个取值';
    case REASON.MALFORMED:
      return 'Accept-CH-Lifetime 取值无法解析';
    default:
      return 'Accept-CH-Lifetime 未知状态';
  }
}

module.exports = {
  REASON,
  inspectAcceptChLifetime,
  applyAcceptChLifetimeGuard,
  describeReason,
};
