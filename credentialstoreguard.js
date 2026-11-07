'use strict';

const REASON = {
  OK: 'ok',
  PLAINTEXT_STORE: 'credential-plaintext-store',
  UNKNOWN_BACKEND: 'credential-unknown-backend',
  WEAK_ENCRYPTION: 'credential-weak-encryption',
  FILE_WORLD_READABLE: 'credential-world-readable',
  EMPTY_SECRET: 'credential-empty',
  LONG_SECRET: 'credential-too-long',
};

const SAFE_BACKENDS = new Set(['keychain', 'dpapi', 'libsecret', 'safe-storage', 'oscrypt']);
const MAX_SECRET = 4096;

function evaluateCredentialStore(config) {
  const cfg = config || {};
  const backend = String(cfg.backend || '').toLowerCase();
  if (backend === 'plaintext' || backend === 'json' || backend === 'memory') {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT_STORE, backend };
  }
  if (!SAFE_BACKENDS.has(backend)) {
    return { ok: false, blocked: true, reason: REASON.UNKNOWN_BACKEND, backend };
  }
  if (cfg.algorithm && !/^(aes-256-gcm|chacha20-poly1305)$/i.test(String(cfg.algorithm))) {
    return { ok: false, blocked: true, reason: REASON.WEAK_ENCRYPTION, backend, algorithm: cfg.algorithm };
  }
  if (cfg.worldReadable === true) {
    return { ok: false, blocked: true, reason: REASON.FILE_WORLD_READABLE, backend };
  }
  return { ok: true, blocked: false, reason: REASON.OK, backend };
}

function evaluateSecret(secret, options) {
  const opts = options || {};
  const store = evaluateCredentialStore(opts.store || {});
  if (store.blocked) return store;
  if (typeof secret !== 'string' || secret.length === 0) {
    return { ok: false, blocked: true, reason: REASON.EMPTY_SECRET, backend: store.backend };
  }
  if (secret.length > MAX_SECRET) {
    return { ok: false, blocked: true, reason: REASON.LONG_SECRET, backend: store.backend };
  }
  if (opts.requireNonAscii !== true && /^\s*$/.test(secret)) {
    return { ok: false, blocked: true, reason: REASON.EMPTY_SECRET, backend: store.backend };
  }
  return { ok: true, blocked: false, reason: REASON.OK, backend: store.backend, length: secret.length };
}

function auditCredentialBatch(list) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCredentialStore(item);
    if (result.blocked) {
      blocked += 1;
      findings.push({ backend: result.backend, reason: result.reason });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no credential store risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.backend || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateCredentialStore,
  evaluateSecret,
  auditCredentialBatch,
  describeFindings,
};
