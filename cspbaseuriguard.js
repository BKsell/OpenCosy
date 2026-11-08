'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'base-uri-missing',
  WILDCARD: 'base-uri-wildcard',
  CROSS_ORIGIN: 'base-uri-cross-origin',
  PLAINTEXT: 'base-uri-plaintext',
  NOT_STRICT: 'base-uri-not-strict',
};

function evaluateBaseUri(policy) {
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  const directives = text.split(';').map((part) => part.trim()).filter((part) => part !== '');
  let sources = null;
  for (const directive of directives) {
    const parts = directive.split(/\s+/);
    if ((parts[0] || '').toLowerCase() !== 'base-uri') continue;
    sources = parts.slice(1).map((part) => part.toLowerCase());
  }
  if (sources === null || sources.length === 0) {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  if (sources.includes('*')) return { ok: false, blocked: true, reason: REASON.WILDCARD, sources };
  for (const source of sources) {
    if (source.startsWith('http:') || source.startsWith('http://')) {
      return { ok: false, blocked: true, reason: REASON.PLAINTEXT, sources, source };
    }
  }
  const strict = sources.filter((source) => source === "'none'" || source === "'self'").length > 0;
  if (!strict) {
    return { ok: false, blocked: false, reason: REASON.NOT_STRICT, sources };
  }
  const foreign = sources.filter((source) => source !== "'none'" && source !== "'self'");
  if (foreign.length > 0) {
    return { ok: false, blocked: false, reason: REASON.CROSS_ORIGIN, sources, foreign };
  }
  return { ok: true, blocked: false, reason: REASON.OK, sources };
}

function appendBaseUri(policy) {
  const text = typeof policy === 'string' ? policy : '';
  const trimmed = text.trim().replace(/;+$/, '');
  if (trimmed === '') return "base-uri 'none'";
  if (trimmed.toLowerCase().includes('base-uri')) return trimmed;
  return trimmed + "; base-uri 'none'";
}

module.exports = {
  REASON,
  evaluateBaseUri,
  appendBaseUri,
};
