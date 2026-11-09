'use strict';

let d = {};

function bindDeps(next) {
  d = next;
}

function loadCertExceptions() {
  if (d.certExceptionsLoaded) return;
  d.certExceptionsLoaded = true;
  try {
    const data = d.ledgerStore.readJSONStore(d.certExceptionStorePath, {});
    if (data && Array.isArray(data.exceptions)) {
      for (const raw of data.exceptions) {
        const rec = d.certGuard.sanitizeExceptionRecord(raw);
        if (rec) d.certExceptions.push(rec);
      }
      if (d.certExceptions.length > d.MAX_CERT_EXCEPTIONS) {
        d.certExceptions = d.certExceptions.slice(-d.MAX_CERT_EXCEPTIONS);
      }
    }
  } catch {}
}

function persistCertExceptions() {
  if (d.certExceptionSaveTimer) clearTimeout(d.certExceptionSaveTimer);
  d.certExceptionSaveTimer = setTimeout(() => {
    try {
      d.ledgerStore.writeJSONStore(d.certExceptionStorePath, { version: 1, savedAt: Date.now(), exceptions: d.certExceptions });
    } catch {}
  }, 1000);
}

function addCertException(url, certificate, code) {
  const entry = d.certGuard.createException({ host: url, certificate, code });
  if (!entry) return false;
  loadCertExceptions();
  const idx = d.certExceptions.findIndex(e =>
    e.host === entry.host && e.fingerprint === entry.fingerprint);
  if (idx >= 0) {
    d.certExceptions.splice(idx, 1);
  } else if (d.certExceptions.length >= d.MAX_CERT_EXCEPTIONS) {
    d.certExceptions.shift(); // 台账满了淘汰最旧的一条
  }
  d.certExceptions.push(entry);
  persistCertExceptions();
  return true;
}

function removeCertException(host, fingerprint) {
  loadCertExceptions();
  const h = d.certGuard.normalizeHost(host);
  const fp = d.certGuard.normalizeFingerprint(fingerprint);
  const before = d.certExceptions.length;
  d.certExceptions = d.certExceptions.filter(e =>
    !(e.host === h && (!fp || e.fingerprint === fp)));
  if (d.certExceptions.length !== before) persistCertExceptions();
  return true;
}

function clearCertExceptions() {
  loadCertExceptions();
  d.certExceptions = [];
  try { d.fsSync.unlinkSync(d.certExceptionStorePath); } catch {}
  persistCertExceptions();
  return true;
}

function certExceptionAllowed(url, certificate) {
  const verdict = d.certGuard.classifyCertError({ url, certificate });
  if (!verdict.host || !verdict.cert || !verdict.cert.fingerprint) return false;
  loadCertExceptions();
  return d.certExceptions.some(e => d.certGuard.exceptionMatches(e, {
    host: verdict.host,
    fingerprint: verdict.cert.fingerprint,
  }));
}

function getCertExceptionStats() {
  loadCertExceptions();
  const hosts = new Set(d.certExceptions.map(e => e.host));
  return { exceptions: d.certExceptions.length, hosts: hosts.size };
}

function listCertExceptionEntries(limit = 200) {
  loadCertExceptions();
  const n = Math.max(1, Math.min(Number(limit) || 200, d.MAX_CERT_EXCEPTIONS));
  return d.certExceptions.slice(-n).reverse().map(e => ({ ...e }));
}

function sanitizeCertPickList(certificateList) {
  const out = [];
  const list = Array.isArray(certificateList) ? certificateList : [];
  for (let i = 0; i < list.length && i < d.MAX_CLIENT_CERT_PICK_CHARS; i++) {
    const s = d.netAuthGuard.summarizeClientCert(list[i]);
    out.push({
      index: i,
      fingerprint: s.fingerprint,
      issuer: s.issuer,
      subject: s.subject,
      serialNumber: s.serialNumber,
    });
  }
  return out;
}

function makeCertChallenge(verdict, webContentsId) {
  const nonce = require('crypto').randomBytes(16).toString('hex');
  d.certChallenges.set(nonce, {
    host: verdict.host,
    code: verdict.code,
    fingerprint: verdict.cert ? verdict.cert.fingerprint : '',
    webContentsId,
    createdAt: Date.now(),
  });
  setTimeout(() => d.certChallenges.delete(nonce), d.CERT_CHALLENGE_TTL).unref?.();
  return nonce;
}

function consumeCertChallenge(nonce) {
  if (typeof nonce !== 'string' || nonce.length !== 32) return null;
  const c = d.certChallenges.get(nonce);
  if (!c) return null;
  d.certChallenges.delete(nonce);
  if (Date.now() - c.createdAt > d.CERT_CHALLENGE_TTL) return null;
  return c;
}

function failAuthCallback(callback) {
  try { callback(); } catch {}
}

function authEventOrigin(webContents) {
  if (!webContents || typeof webContents.getURL !== 'function') return '';
  return d.urlResolve.safeOrigin(webContents.getURL(), '');
}

function netAuthNonce() {
  return 'na-' + d.netAuthCrypto.randomBytes(12).toString('hex');
}

module.exports = { loadCertExceptions, persistCertExceptions, addCertException, removeCertException, clearCertExceptions, certExceptionAllowed, getCertExceptionStats, listCertExceptionEntries, sanitizeCertPickList, makeCertChallenge, consumeCertChallenge, failAuthCallback, authEventOrigin, netAuthNonce, bindDeps };
