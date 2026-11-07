'use strict';

const REASON = {
  OK: 'ok',
  EXPIRED: 'certificate-expired',
  HOSTNAME_MISMATCH: 'hostname-mismatch',
  SELF_SIGNED: 'self-signed',
  WEAK_SIGNATURE: 'weak-signature',
  UNTRUSTED_CHAIN: 'untrusted-chain',
  HSTS_HOST: 'hsts-host-error',
  USER_BYPASS: 'user-bypass-forbidden',
};

const WEAK_ALGS = new Set(['md5', 'sha1', 'sha1withrsa', 'md5withrsa']);

function daysLeft(validTo) {
  const end = Date.parse(validTo);
  if (!Number.isFinite(end)) return -1;
  return Math.floor((end - Date.now()) / 86400000);
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const cert = req.cert && typeof req.cert === 'object' ? req.cert : null;
  const urgent = req.bypass === true;
  if (urgent && !req.allowUserBypass) return { action: 'block', reason: REASON.USER_BYPASS };
  if (!cert) return { action: 'block', reason: REASON.UNTRUSTED_CHAIN };
  if (daysLeft(cert.validTo) < 0) return { action: 'block', reason: REASON.EXPIRED };
  if (cert.subjectName && req.host && String(cert.subjectName).toLowerCase() !== String(req.host).toLowerCase()) {
    const san = Array.isArray(cert.san) ? cert.san.map((s) => String(s).toLowerCase()) : [];
    if (!san.includes(String(req.host).toLowerCase())) return { action: 'block', reason: REASON.HOSTNAME_MISMATCH };
  }
  if (cert.selfSigned) return { action: 'block', reason: REASON.SELF_SIGNED };
  if (WEAK_ALGS.has(String(cert.signatureAlgorithm || '').toLowerCase())) {
    return { action: 'block', reason: REASON.WEAK_SIGNATURE };
  }
  if (req.hstsHost && !cert.trusted) return { action: 'block', reason: REASON.HSTS_HOST };
  if (!cert.trusted) return { action: 'confirm', reason: REASON.UNTRUSTED_CHAIN };
  return { action: 'allow', reason: REASON.OK };
}

function applyCertificateErrorPolicyGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  return {
    action: result.action,
    blocked: result.action === 'block',
    reason: result.reason,
    showInterstitial: result.action !== 'allow',
    allowPermanent: false,
  };
}

function auditCertificateBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.action === 'block') blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ host: item && item.host, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no certificate policy risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyCertificateErrorPolicyGuard,
  auditCertificateBatch,
  describeFindings,
};
