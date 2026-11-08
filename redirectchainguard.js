'use strict';

const REASON = {
  OK: 'ok',
  TOO_MANY_HOPS: 'redirect-too-many-hops',
  DOWNGRADE: 'redirect-scheme-downgrade',
  CROSS_SCHEME: 'redirect-cross-scheme',
  CREDENTIAL_LEAK: 'redirect-credential-leak',
  INVALID: 'redirect-invalid-location',
  LOOP: 'redirect-loop',
  BACK_TO_HTTP: 'redirect-back-to-http',
};

const MAX_HOPS = 10;
const MAX_URL = 8192;
const SAFE = new Set(['https:', 'http:', 'wss:', 'ws:', 'file:', 'about:']);

function parse(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function evaluateRedirectChain(chain, options) {
  const opts = options || {};
  const maxHops = Number(opts.maxHops) > 0 ? Number(opts.maxHops) : MAX_HOPS;
  const list = Array.isArray(chain) ? chain.map(parse) : [];
  if (list.length === 0 || list.some((item) => !item)) {
    return { ok: false, blocked: true, reason: REASON.INVALID, hops: list.length };
  }
  if (list.length - 1 > maxHops) {
    return { ok: false, blocked: true, reason: REASON.TOO_MANY_HOPS, hops: list.length - 1 };
  }
  const seen = new Set([list[0].href]);
  for (let i = 1; i < list.length; i += 1) {
    const prev = list[i - 1];
    const next = list[i];
    if (!SAFE.has(next.protocol)) {
      return { ok: false, blocked: true, reason: REASON.CROSS_SCHEME, hop: i, url: next.href };
    }
    if (prev.protocol === 'https:' && next.protocol === 'http:') {
      const local = next.hostname === 'localhost' || next.hostname === '127.0.0.1';
      if (!local) return { ok: false, blocked: true, reason: REASON.DOWNGRADE, hop: i, url: next.href };
    }
    if (seen.has(next.href)) {
      return { ok: false, blocked: true, reason: REASON.LOOP, hop: i, url: next.href };
    }
    seen.add(next.href);
    if ((next.username || next.password) && next.origin !== prev.origin) {
      return { ok: false, blocked: true, reason: REASON.CREDENTIAL_LEAK, hop: i, url: next.href };
    }
  }
  return { ok: true, blocked: false, reason: REASON.OK, hops: list.length - 1, finalUrl: list[list.length - 1].href };
}

function auditRedirectBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateRedirectChain(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, hop: result.hop, url: result.url });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no redirect risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.url || ('hop ' + (f.hop || 0))) + ')')
    .join('; ');
}

module.exports = {
  REASON,
  MAX_HOPS,
  evaluateRedirectChain,
  auditRedirectBatch,
  describeFindings,
};
