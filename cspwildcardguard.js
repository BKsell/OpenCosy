'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'csp-wildcard-empty',
  STAR: 'csp-source-star',
  SCHEME_ONLY: 'csp-scheme-only',
  DATA_BLOB: 'csp-data-blob',
  UNSAFE_INLINE: 'csp-unsafe-inline',
  UNSAFE_EVAL: 'csp-unsafe-eval',
};

const DANGEROUS = ['data:', 'blob:', 'filesystem:'];
const KEYWORDS = ['unsafe-inline', 'unsafe-eval'];

function evaluateCspSources(policy, options) {
  const opts = options || {};
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY, findings: [] };
  }
  const directives = text.split(';').map((part) => part.trim()).filter((part) => part !== '');
  const targets = opts.directives && opts.directives.length > 0
    ? opts.directives.map((d) => d.toLowerCase())
    : ['script-src', 'default-src'];
  const findings = [];
  for (const directive of directives) {
    const parts = directive.split(/\s+/);
    const name = (parts[0] || '').toLowerCase();
    if (!targets.includes(name)) continue;
    for (const raw of parts.slice(1)) {
      const source = raw.toLowerCase();
      if (source === '*') findings.push({ reason: REASON.STAR, directive: name, source });
      else if (DANGEROUS.includes(source)) findings.push({ reason: REASON.DATA_BLOB, directive: name, source });
      else if (source.endsWith(':') || source === 'http:' || source === 'https:') {
        findings.push({ reason: REASON.SCHEME_ONLY, directive: name, source });
      } else if (KEYWORDS.includes(source.replace(/'/g, ''))) {
        findings.push({
          reason: source.includes('eval') ? REASON.UNSAFE_EVAL : REASON.UNSAFE_INLINE,
          directive: name,
          source,
        });
      }
    }
  }
  if (findings.length > 0) {
    return { ok: false, blocked: true, reason: findings[0].reason, findings };
  }
  return { ok: true, blocked: false, reason: REASON.OK, findings: [] };
}

function countSources(policy) {
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') return 0;
  let count = 0;
  for (const directive of text.split(';')) {
    const parts = directive.trim().split(/\s+/);
    if (parts[0] === '') continue;
    count += Math.max(parts.length - 1, 0);
  }
  return count;
}

module.exports = {
  REASON,
  DANGEROUS,
  KEYWORDS,
  evaluateCspSources,
  countSources,
};
