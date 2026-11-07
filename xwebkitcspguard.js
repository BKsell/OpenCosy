'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  LEGACY_CSP: 'legacy-csp',
  CONFLICT: 'conflict',
};

const LEGACY_HEADERS = ['x-webkit-csp', 'x-content-security-policy', 'x-webkit-csp-report-only'];

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

function collectLegacy(headers) {
  const removed = [];
  for (const name of LEGACY_HEADERS) {
    const key = headerKey(headers, name);
    if (!key) continue;
    const raw = headers[key];
    delete headers[key];
    removed.push({ header: name, value: Array.isArray(raw) ? raw.slice(0, 2) : raw });
  }
  return removed;
}

function applyXWebKitCspGuard(headers) {
  const removed = collectLegacy(headers);
  if (removed.length === 0) {
    return { changed: false, reason: REASON.MISSING };
  }
  const hasModernCsp = Boolean(headerKey(headers, 'content-security-policy'))
    || Boolean(headerKey(headers, 'content-security-policy-report-only'));
  return {
    changed: true,
    reason: hasModernCsp ? REASON.CONFLICT : REASON.LEGACY_CSP,
    removed,
    count: removed.length,
  };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return '未发现旧版 CSP 头';
    case REASON.MISSING:
      return '未声明旧版 CSP 头';
    case REASON.LEGACY_CSP:
      return '旧版 X-WebKit-CSP 已移除，只保留标准 CSP';
    case REASON.CONFLICT:
      return '旧版 CSP 头与标准 CSP 并存，已移除旧版';
    default:
      return '旧版 CSP 头状态未知';
  }
}

module.exports = {
  REASON,
  applyXWebKitCspGuard,
  describeReason,
};
