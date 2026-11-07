'use strict';

const REASON = {
  OK: 'ok',
  HOME_PATH: 'home-path',
  EMAIL: 'email-address',
  TOKEN: 'secret-token',
  IP: 'internal-ip',
  USERNAME: 'username-path',
  TOO_LARGE: 'report-too-large',
};

const PATTERNS = [
  { reason: 'home-path', re: /(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)[^\\/\s]+/g },
  { reason: 'email-address', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { reason: 'secret-token', re: /\b(?:ghp_|github_pat_|sk-[A-Za-z0-9]{10,}|Bearer\s+[A-Za-z0-9._-]{16,}|AKIA[0-9A-Z]{16})/g },
  { reason: 'internal-ip', re: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g },
];

function scrub(text, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const maxLength = Number(opts.maxLength) || 512 * 1024;
  if (typeof text !== 'string') return { text: '', redactions: 0, reasons: [] };
  if (text.length > maxLength) {
    return { text: text.slice(0, maxLength), redactions: 1, reasons: [REASON.TOO_LARGE], truncated: true };
  }
  let out = text;
  const reasons = [];
  let redactions = 0;
  for (const item of PATTERNS) {
    out = out.replace(item.re, () => {
      redactions += 1;
      if (!reasons.includes(item.reason)) reasons.push(item.reason);
      return '<redacted>';
    });
  }
  return { text: out, redactions, reasons, truncated: false };
}

function applyCrashReportScrubGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = scrub(req.body, { maxLength: req.maxLength });
  return {
    body: result.text,
    redactions: result.redactions,
    reasons: result.reasons,
    truncated: result.truncated,
    changed: result.redactions > 0,
    reason: result.reasons.length > 0 ? result.reasons[0] : REASON.OK,
  };
}

function auditCrashBatch(reports, options) {
  const list = Array.isArray(reports) ? reports : [];
  const findings = [];
  let redacted = 0;
  for (const item of list) {
    const result = scrub(item && item.body, options);
    if (result.redactions > 0) redacted += 1;
    if (result.redactions > 0) findings.push({ reason: result.reasons[0], redactions: result.redactions });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { redacted, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no crash report risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyCrashReportScrubGuard,
  auditCrashBatch,
  describeFindings,
  scrub,
};
