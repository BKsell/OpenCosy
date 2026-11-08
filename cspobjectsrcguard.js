'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'object-src-missing',
  WILDCARD: 'object-src-wildcard',
  NOT_NONE: 'object-src-not-none',
  PLUGIN_TYPES: 'object-src-plugin-types',
};

const PLUGIN_SOURCES = ['data:', 'blob:', 'filesystem:', 'http:', 'https:'];

function evaluateObjectSrc(policy) {
  const text = typeof policy === 'string' ? policy : '';
  if (text.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  const directives = text.split(';').map((part) => part.trim()).filter((part) => part !== '');
  let sources = null;
  let pluginTypes = null;
  for (const directive of directives) {
    const parts = directive.split(/\s+/);
    const name = (parts[0] || '').toLowerCase();
    if (name === 'object-src') sources = parts.slice(1).map((part) => part.toLowerCase());
    if (name === 'plugin-types') pluginTypes = parts.slice(1).map((part) => part.toLowerCase());
  }
  if (sources === null || sources.length === 0) {
    return { ok: false, blocked: true, reason: REASON.MISSING, sources: [] };
  }
  if (sources.includes('*')) return { ok: false, blocked: true, reason: REASON.WILDCARD, sources };
  if (sources.length !== 1 || sources[0] !== "'none'") {
    const risky = sources.filter((source) => PLUGIN_SOURCES.includes(source));
    return {
      ok: false,
      blocked: true,
      reason: risky.length > 0 ? REASON.PLUGIN_TYPES : REASON.NOT_NONE,
      sources,
      risky,
    };
  }
  if (pluginTypes !== null && pluginTypes.length > 0) {
    return { ok: false, blocked: true, reason: REASON.PLUGIN_TYPES, sources, pluginTypes };
  }
  return { ok: true, blocked: false, reason: REASON.OK, sources };
}

function harden(policy) {
  const text = typeof policy === 'string' ? policy : '';
  const trimmed = text.trim().replace(/;+$/, '');
  if (trimmed === '') return "object-src 'none'";
  if (/(^|;)\s*object-src/i.test(trimmed)) return trimmed;
  return trimmed + "; object-src 'none'";
}

module.exports = {
  REASON,
  PLUGIN_SOURCES,
  evaluateObjectSrc,
  harden,
};
