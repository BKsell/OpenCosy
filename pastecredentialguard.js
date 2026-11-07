'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'empty-paste',
  TOO_LARGE: 'paste-too-large',
  SECRET_PATTERN: 'secret-pattern',
  CONTROL_CHARS: 'control-characters',
  PASSWORD_FIELD: 'password-field-paste',
};

const SECRET_PATTERNS = [
  /ghp_[A-Za-z0-9]{20,}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /sk-[A-Za-z0-9]{16,}/,
  /AKIA[0-9A-Z]{16}/,
  /-----BEGIN [A-Z ]+PRIVATE KEY-----/,
];

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const text = typeof req.text === 'string' ? req.text : '';
  if (!text.trim()) return { blocked: true, reason: REASON.EMPTY };
  if (text.length > (Number(req.maxLength) || 4096)) return { blocked: true, reason: REASON.TOO_LARGE };
  if (SECRET_PATTERNS.some((re) => re.test(text))) return { blocked: true, reason: REASON.SECRET_PATTERN };
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text)) return { blocked: true, reason: REASON.CONTROL_CHARS };
  if (req.fieldType === 'password' && req.multiline !== true) {
    return { blocked: true, reason: REASON.PASSWORD_FIELD };
  }
  return { blocked: false, reason: REASON.OK };
}

function applyPasteCredentialGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const text = result.blocked && result.reason === REASON.CONTROL_CHARS ? String(req.text || '').replace(/[\u0000-\u001f]/g, '') : String(req.text || '');
  return {
    blocked: result.blocked,
    reason: result.reason,
    text: result.blocked ? '' : text,
    length: result.blocked ? 0 : text.length,
  };
}

function auditPasteBatch(events, options) {
  const list = Array.isArray(events) ? events : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.blocked) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ fieldType: item && item.fieldType, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no paste risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyPasteCredentialGuard,
  auditPasteBatch,
  describeFindings,
};
