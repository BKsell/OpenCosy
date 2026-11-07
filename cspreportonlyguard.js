'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_REPORT_URI: 'bad-report-uri',
  OVERLONG: 'overlong',
  MISSING_DIRECTIVE: 'missing-directive',
};

const HEADER = 'content-security-policy-report-only';
const MAX_LENGTH = 4096;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function policyValue(headers) {
  const key = headerKey(headers, HEADER);
  if (!key) return null;
  const raw = headers[key];
  return Array.isArray(raw) ? raw.join(';') : raw;
}

function isSecureUri(value) {
  const text = value.trim();
  if (!text) return true;
  return /^https:\/\//i.test(text);
}

function stripInsecureReports(policy) {
  const parts = policy.split(';').map((v) => v.trim()).filter(Boolean);
  const kept = [];
  let dropped = false;
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (lower.startsWith('report-uri ') || lower.startsWith('report-to ')) {
      const values = part.split(/\s+/).slice(1);
      const secure = values.filter((uri) => isSecureUri(uri));
      if (secure.length !== values.length) dropped = true;
      if (secure.length > 0) kept.push(part.split(/\s+/)[0].toLowerCase() + ' ' + secure.join(' '));
      continue;
    }
    kept.push(part);
  }
  return { policy: kept.join('; '), dropped };
}

function hasEnforcementDirective(policy) {
  const lower = policy.toLowerCase();
  return /(^|;)\s*(default-src|script-src|object-src|frame-ancestors)\b/.test(lower);
}

function applyCspReportOnlyGuard(headers) {
  const raw = policyValue(headers);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  if (typeof raw !== 'string') {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  const text = raw.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const sanitized = stripInsecureReports(text);
  if (!hasEnforcementDirective(sanitized.policy)) {
    sanitized.policy = "default-src 'self'; " + sanitized.policy;
    headers[headerKey(headers, HEADER)] = sanitized.policy;
    return { changed: true, reason: REASON.MISSING_DIRECTIVE };
  }
  if (sanitized.dropped) {
    headers[headerKey(headers, HEADER)] = sanitized.policy;
    return { changed: true, reason: REASON.BAD_REPORT_URI };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCspReportOnlyGuard };
