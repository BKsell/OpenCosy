'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'csp-report-empty',
  PLAINTEXT_ENDPOINT: 'csp-report-plaintext',
  CREDENTIALS: 'csp-report-credentials',
  NO_GROUP: 'csp-report-no-group',
  OVERSIZED_GROUP: 'csp-report-oversized',
  LEGACY_ONLY: 'csp-report-legacy-only',
};

const MAX_GROUPS = 8;

function evaluateReportGroup(group) {
  const item = group || {};
  const name = typeof item.name === 'string' ? item.name : '';
  const endpoints = Array.isArray(item.endpoints) ? item.endpoints : [];
  if (name.trim() === '' || endpoints.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, name };
  }
  if (endpoints.length > MAX_GROUPS) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED_GROUP, name, count: endpoints.length };
  }
  for (const raw of endpoints) {
    let url;
    try {
      url = new URL(String(raw));
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.EMPTY, name, endpoint: String(raw).slice(0, 48) };
    }
    if (url.protocol !== 'https:') {
      return { ok: false, blocked: true, reason: REASON.PLAINTEXT_ENDPOINT, name, endpoint: url.protocol };
    }
    if (url.username || url.password) {
      return { ok: false, blocked: true, reason: REASON.CREDENTIALS, name, endpoint: url.origin };
    }
    if (url.pathname === '/' || url.pathname.length < 3) {
      return { ok: false, blocked: true, reason: REASON.NO_GROUP, name, endpoint: url.href };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, name, count: endpoints.length };
}

function evaluateReportPolicy(headers) {
  const list = Array.isArray(headers) ? headers : [];
  let hasReportTo = false;
  let hasReportUri = false;
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    const name = String(entry[0] || '').toLowerCase();
    if (name === 'report-to') hasReportTo = true;
    if (name === 'content-security-policy' && String(entry[1] || '').toLowerCase().includes('report-uri')) {
      hasReportUri = true;
    }
  }
  if (!hasReportTo && hasReportUri) {
    return { ok: false, blocked: false, reason: REASON.LEGACY_ONLY, hasReportTo, hasReportUri };
  }
  if (!hasReportTo && !hasReportUri) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, hasReportTo, hasReportUri };
  }
  return { ok: true, blocked: false, reason: REASON.OK, hasReportTo, hasReportUri };
}

module.exports = {
  REASON,
  MAX_GROUPS,
  evaluateReportGroup,
  evaluateReportPolicy,
};
