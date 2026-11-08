'use strict';

const REASON = {
  OK: 'ok',
  HSTS_MISSING: 'hsts-missing',
  XCTO_MISSING: 'nosniff-missing',
  FRAME_OPEN: 'frame-open',
  REFERRER_WEAK: 'referrer-weak',
  CSP_MISSING: 'csp-missing',
  CSP_UNSAFE: 'csp-unsafe-inline',
  SERVER_BANNER: 'server-banner',
};

function lowerHeaders(headers) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const key of Object.keys(headers)) out[key.toLowerCase()] = String(headers[key]);
  return out;
}

function hasUnsafeInline(csp) {
  return /unsafe-inline|unsafe-eval/i.test(csp);
}

function audit(headers) {
  const h = lowerHeaders(headers);
  const findings = [];
  if (!h['strict-transport-security']) findings.push({ reason: REASON.HSTS_MISSING, detail: 'Strict-Transport-Security' });
  if (h['x-content-type-options'] !== 'nosniff') findings.push({ reason: REASON.XCTO_MISSING, detail: 'X-Content-Type-Options' });
  const xfo = h['x-frame-options'] || '';
  const csp = h['content-security-policy'] || '';
  if (!xfo && !/frame-ancestors/.test(csp)) findings.push({ reason: REASON.FRAME_OPEN, detail: 'X-Frame-Options' });
  const referrer = (h['referrer-policy'] || '').toLowerCase();
  if (!referrer || referrer === 'unsafe-url' || referrer === 'no-referrer-when-downgrade') {
    findings.push({ reason: REASON.REFERRER_WEAK, detail: referrer || 'missing' });
  }
  if (!csp) findings.push({ reason: REASON.CSP_MISSING, detail: 'Content-Security-Policy' });
  else if (hasUnsafeInline(csp)) findings.push({ reason: REASON.CSP_UNSAFE, detail: 'unsafe-inline' });
  if (h.server || h['x-powered-by']) findings.push({ reason: REASON.SERVER_BANNER, detail: h.server ? 'Server' : 'X-Powered-By' });
  return { score: 7 - findings.length, findings };
}

function buildHeaders(options) {
  const opts = options && typeof options === 'object' ? options : {};
  return {
    'Strict-Transport-Security': opts.hsts || 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': opts.frameOptions || 'DENY',
    'Referrer-Policy': opts.referrerPolicy || 'strict-origin-when-cross-origin',
    'Content-Security-Policy': opts.csp || "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
  };
}

function applySecurityHeadersGuard(response) {
  const res = response && typeof response === 'object' ? response : {};
  const auditResult = audit(res.headers);
  const headers = Object.assign({}, res.headers || {});
  const defaults = buildHeaders(res.options || {});
  let changed = false;
  for (const key of Object.keys(defaults)) {
    if (!headers[key] && !lowerHeaders(headers)[key.toLowerCase()]) {
      headers[key] = defaults[key];
      changed = true;
    }
  }
  delete headers.Server;
  delete headers['X-Powered-By'];
  return { headers, changed, score: auditResult.score, findings: auditResult.findings };
}

function auditHeaderBatch(responses, options) {
  const list = Array.isArray(responses) ? responses : [];
  const findings = [];
  let weak = 0;
  for (const item of list) {
    const result = audit(item && item.headers);
    if (result.findings.length > 0) weak += 1;
    for (const f of result.findings) findings.push({ url: item && item.url, reason: f.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { weak, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no header risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applySecurityHeadersGuard,
  auditHeaderBatch,
  buildHeaders,
  describeFindings,
};
