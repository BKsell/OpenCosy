'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'frame-ancestors-missing',
  WILDCARD: 'frame-ancestors-wildcard',
  PLAINTEXT: 'frame-ancestors-plaintext',
  CROSS_ORIGIN: 'frame-ancestors-cross-origin',
  XFO_BOTH: 'frame-ancestors-xfo-conflict',
};

function evaluateFrameAncestors(policy, options) {
  const opts = options || {};
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  const directives = text.split(';').map((part) => part.trim()).filter((part) => part !== '');
  let sources = null;
  for (const directive of directives) {
    const parts = directive.split(/\s+/);
    if ((parts[0] || '').toLowerCase() !== 'frame-ancestors') continue;
    sources = parts.slice(1).map((part) => part.toLowerCase());
  }
  if (sources === null) {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  if (sources.length === 0) {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  if (sources.includes('*')) {
    return { ok: false, blocked: true, reason: REASON.WILDCARD, sources };
  }
  for (const source of sources) {
    if (source.startsWith('http:')) {
      return { ok: false, blocked: true, reason: REASON.PLAINTEXT, sources, source };
    }
  }
  if (opts.selfOnly === true) {
    const extra = sources.filter((source) => source !== "'self'" && source !== "'none'");
    if (extra.length > 0) {
      return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, sources, extra };
    }
  }
  if (opts.xFrameOptions === 'sameorigin' && sources.includes('*')) {
    return { ok: false, blocked: true, reason: REASON.XFO_BOTH, sources };
  }
  return { ok: true, blocked: false, reason: REASON.OK, sources };
}

function buildHeader(sources) {
  const list = Array.isArray(sources) ? sources : [];
  if (list.length === 0) return "frame-ancestors 'none'";
  return 'frame-ancestors ' + list.join(' ');
}

module.exports = {
  REASON,
  evaluateFrameAncestors,
  buildHeader,
};
