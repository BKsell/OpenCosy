'use strict';

const REASON = {
  OK: 'ok',
  NOT_OBJECT: 'csp-report-invalid',
  SECRET_QUERY: 'csp-report-secret-query',
  CREDENTIALS: 'csp-report-credentials',
  FRAGMENT_LEAK: 'csp-report-fragment',
  SENSITIVE_PATH: 'csp-report-sensitive-path',
  LONG_URL: 'csp-report-url-too-long',
  CONTROL_CHARS: 'csp-report-control-chars',
};

const MAX_URL = 4096;
const SECRET_QUERY = /(token|key|secret|password|passwd|auth|session|sig|signature|code)=/i;
const SENSITIVE_PATH = ['/reset/', '/verify/', '/login', '/oauth', '/token'];

function redactUrl(value, options) {
  const opts = options || {};
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, blocked: true, reason: REASON.NOT_OBJECT, url: '' };
  }
  if (value.length > MAX_URL) {
    return { ok: false, blocked: true, reason: REASON.LONG_URL, url: value.slice(0, 64) + '...' };
  }
  if (/[\u0000-\u001f]/.test(value)) {
    return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, url: '' };
  }
  let url;
  try {
    url = new URL(value);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.NOT_OBJECT, url: value.slice(0, 64) };
  }
  let redacted = url.origin + url.pathname;
  if (SENSITIVE_PATH.some((hint) => url.pathname.toLowerCase().includes(hint))) {
    redacted = url.origin + '/redacted';
  }
  if (url.username || url.password) {
    redacted = url.origin + redacted.slice(url.origin.length);
  }
  if (opts.keepQuery === true && url.search && !SECRET_QUERY.test(url.search)) {
    redacted += url.search;
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: redacted };
}

function evaluateCspReport(report, options) {
  if (!report || typeof report !== 'object') {
    return { ok: false, blocked: true, reason: REASON.NOT_OBJECT, url: '' };
  }
  const body = report['csp-report'] || report.body || report;
  const documentUrl = body['document-uri'] || body.documentURL || body.documentUrl;
  if (typeof documentUrl !== 'string' || documentUrl.length === 0) {
    return { ok: false, blocked: true, reason: REASON.NOT_OBJECT, url: '' };
  }
  const result = redactUrl(documentUrl, options);
  if (!result.ok) return result;
  const auxFields = [body.referrer, body['blocked-uri'], body['source-file'], body['script-sample']];
  for (const field of auxFields) {
    if (typeof field === 'string' && /[\u0000-\u001f]/.test(field)) {
      return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, url: result.url };
    }
  }
  if (body.referrer && SECRET_QUERY.test(String(body.referrer))) {
    return { ok: false, blocked: true, reason: REASON.SECRET_QUERY, url: result.url };
  }
  const blocked = body['blocked-uri'] || body.blockedURL || '';
  if (typeof blocked === 'string' && SECRET_QUERY.test(blocked)) {
    return { ok: false, blocked: true, reason: REASON.SECRET_QUERY, url: result.url };
  }
  return { ok: true, blocked: false, reason: REASON.OK, url: result.url, report: { 'document-uri': result.url } };
}

function auditCspReportBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCspReport(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, url: result.url });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no csp report leak';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  redactUrl,
  evaluateCspReport,
  auditCspReportBatch,
  describeFindings,
};
