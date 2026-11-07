'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  OVERLONG: 'overlong',
  UNSAFE_SOURCE: 'unsafe-source',
  MISSING_DIRECTIVE: 'missing-default-src',
  BAD_REPORT_URI: 'bad-report-uri',
  EMPTY: 'empty',
};

const HEADER = 'content-security-policy';
const MAX_LENGTH = 8192;
const SCRIPT_DIRECTIVES = new Set(['script-src', 'script-src-elem', 'script-src-attr', 'object-src', 'default-src']);
const UNSAFE_SOURCES = new Set(['*', 'http:', 'data:', 'blob:', 'filesystem:']);

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

function parseDirectives(text) {
  const output = [];
  for (const part of text.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const fields = trimmed.split(/\s+/);
    const name = fields.shift().toLowerCase();
    output.push({ name, values: fields.map((value) => value.toLowerCase()) });
  }
  return output;
}

function sanitizeDirective(directive) {
  if (!SCRIPT_DIRECTIVES.has(directive.name)) return directive;
  const kept = [];
  let dropped = false;
  for (const value of directive.values) {
    if (UNSAFE_SOURCES.has(value)) {
      dropped = true;
      continue;
    }
    if (value.startsWith('http://')) {
      dropped = true;
      continue;
    }
    kept.push(value);
  }
  if (dropped && kept.length === 0) kept.push("'self'");
  return { name: directive.name, values: kept };
}

function applyCspEnforceGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.EMPTY };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const directives = parseDirectives(text);
  if (directives.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.EMPTY };
  }
  let unsafe = false;
  const rebuilt = [];
  for (const directive of directives) {
    const sanitized = sanitizeDirective(directive);
    if (sanitized.values.length !== directive.values.length) unsafe = true;
    if (sanitized.name === 'report-uri') {
      for (const uri of sanitized.values) {
        if (uri.startsWith('http://')) {
          unsafe = true;
          continue;
        }
        rebuilt.push('report-uri ' + uri);
      }
      continue;
    }
    rebuilt.push(sanitized.values.length ? sanitized.name + ' ' + sanitized.values.join(' ') : sanitized.name);
  }
  const hasDefault = directives.some((directive) => directive.name === 'default-src');
  if (!hasDefault) {
    rebuilt.unshift("default-src 'self'");
  }
  const serialized = rebuilt.join('; ');
  if (serialized !== text) {
    headers[headerKey(headers, HEADER)] = serialized;
    const reason = unsafe ? REASON.UNSAFE_SOURCE : hasDefault ? REASON.OK : REASON.MISSING_DIRECTIVE;
    return { changed: true, reason: reason === REASON.OK ? REASON.MISSING_DIRECTIVE : reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyCspEnforceGuard };
