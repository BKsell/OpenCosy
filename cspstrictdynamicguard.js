'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'strict-dynamic-empty',
  NO_TRUST_ANCHOR: 'strict-dynamic-no-trust-anchor',
  UNTRUSTED_ANCHOR: 'strict-dynamic-untrusted-anchor',
  LEGACY_FALLBACK: 'strict-dynamic-legacy-fallback',
};

function evaluateStrictDynamic(policy) {
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, anchors: [] };
  }
  const directives = text.split(';').map((part) => part.trim()).filter((part) => part !== '');
  const findings = [];
  const anchors = [];
  for (const directive of directives) {
    const parts = directive.split(/\s+/);
    const name = (parts[0] || '').toLowerCase();
    if (name !== 'script-src' && name !== 'script-src-elem' && name !== 'default-src') continue;
    const sources = parts.slice(1).map((part) => part.toLowerCase());
    if (!sources.includes("'strict-dynamic'")) continue;
    const nonce = sources.filter((source) => source.startsWith("'nonce-"));
    const hash = sources.filter((source) => source.startsWith("'sha256-") || source.startsWith("'sha384-") || source.startsWith("'sha512-"));
    if (nonce.length === 0 && hash.length === 0) {
      findings.push({ reason: REASON.NO_TRUST_ANCHOR, directive: name });
    } else {
      anchors.push({ directive: name, nonce: nonce.length, hash: hash.length });
    }
    const legacy = sources.filter((source) => source === 'http:' || source === 'https:' || source === '*' || source === 'data:');
    if (legacy.length > 0) {
      findings.push({ reason: REASON.LEGACY_FALLBACK, directive: name, legacy });
    }
  }
  const strictCount = anchors.length + findings.filter((f) => f.reason === REASON.NO_TRUST_ANCHOR).length;
  if (strictCount === 0) {
    return { ok: false, blocked: true, reason: REASON.NO_TRUST_ANCHOR, anchors: [] };
  }
  if (findings.length > 0) {
    return { ok: false, blocked: true, reason: findings[0].reason, findings, anchors };
  }
  return { ok: true, blocked: false, reason: REASON.OK, anchors };
}

function stripLegacySources(policy) {
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') return '';
  return text
    .split(';')
    .map((directive) => {
      const parts = directive.trim().split(/\s+/);
      if (parts[0] === '') return '';
      const kept = parts.filter((part, index) => {
        if (index === 0) return true;
        const lower = part.toLowerCase();
        return !(lower === '*' || lower === 'http:' || lower === 'https:' || lower === 'data:');
      });
      return kept.join(' ');
    })
    .filter((directive) => directive !== '')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateStrictDynamic,
  stripLegacySources,
};
