'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OVERLONG: 'overlong',
  UNKNOWN_DIRECTIVE: 'unknown-directive',
  DUPLICATE_DIRECTIVE: 'duplicate-directive',
  EMPTY_DIRECTIVE: 'empty-directive',
};

const HEADER = 'content-security-policy';
const MAX_LENGTH = 8192;
const MAX_DIRECTIVES = 24;
const KNOWN = new Set([
  'base-uri',
  'child-src',
  'connect-src',
  'default-src',
  'font-src',
  'form-action',
  'frame-ancestors',
  'frame-src',
  'img-src',
  'manifest-src',
  'media-src',
  'object-src',
  'plugin-types',
  'report-to',
  'report-uri',
  'require-trusted-types-for',
  'sandbox',
  'script-src',
  'script-src-attr',
  'script-src-elem',
  'style-src',
  'style-src-attr',
  'style-src-elem',
  'trusted-types',
  'upgrade-insecure-requests',
  'worker-src',
]);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function applyContentSecurityPolicyGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const parts = text.split(';');
  const seen = new Set();
  const kept = [];
  let unknown = false;
  let duplicate = false;
  let empty = false;
  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const space = trimmed.search(/\s/);
    const name = (space >= 0 ? trimmed.slice(0, space) : trimmed).toLowerCase();
    if (!KNOWN.has(name)) {
      unknown = true;
      continue;
    }
    if (seen.has(name)) {
      duplicate = true;
      continue;
    }
    const rest = space >= 0 ? trimmed.slice(space).trim() : '';
    if (name !== 'upgrade-insecure-requests' && name !== 'sandbox' && !rest) {
      empty = true;
      continue;
    }
    seen.add(name);
    kept.push(rest ? name + ' ' + rest : name);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: unknown ? REASON.UNKNOWN_DIRECTIVE : REASON.EMPTY_DIRECTIVE };
  }
  if (kept.length > MAX_DIRECTIVES) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  if (unknown || duplicate || empty || kept.length !== parts.filter((part) => part.trim()).length) {
    headers[headerKey(headers, HEADER)] = kept.join('; ');
    const reason = unknown ? REASON.UNKNOWN_DIRECTIVE : duplicate ? REASON.DUPLICATE_DIRECTIVE : REASON.EMPTY_DIRECTIVE;
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyContentSecurityPolicyGuard };
