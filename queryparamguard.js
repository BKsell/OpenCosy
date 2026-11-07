'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'query-empty',
  DUPLICATE_PARAM: 'query-duplicate',
  PROTOTYPE_KEY: 'query-prototype-key',
  NESTED_PARAM: 'query-nested',
  OVERSIZED: 'query-oversized',
  CONTROL_CHARS: 'query-control-chars',
};

const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];
const MAX_QUERY = 2048;

function evaluateQuery(query, options) {
  const opts = options || {};
  const text = String(query || '').replace(/^\\?/, '');
  if (text === '') return { ok: true, blocked: false, reason: REASON.EMPTY, params: [] };
  if (text.length > (opts.maxBytes || MAX_QUERY)) {
    return { ok: false, blocked: true, reason: REASON.OVERSIZED, size: text.length, limit: opts.maxBytes || MAX_QUERY };
  }
  const params = [];
  const seen = new Set();
  for (const pair of text.split('&')) {
    if (pair === '') continue;
    const eq = pair.indexOf('=');
    const rawName = eq === -1 ? pair : pair.slice(0, eq);
    let name;
    try {
      name = decodeURIComponent(rawName);
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, param: rawName.slice(0, 32) };
    }
    if (/[\u0000-\u001f]/.test(name)) {
      return { ok: false, blocked: true, reason: REASON.CONTROL_CHARS, param: name.slice(0, 32) };
    }
    if (DANGEROUS_KEYS.includes(name.toLowerCase())) {
      return { ok: false, blocked: true, reason: REASON.PROTOTYPE_KEY, param: name };
    }
    if (name.includes('[') || name.includes(']')) {
      return { ok: false, blocked: true, reason: REASON.NESTED_PARAM, param: name.slice(0, 48) };
    }
    const key = name.toLowerCase();
    if (seen.has(key)) {
      return { ok: false, blocked: false, reason: REASON.DUPLICATE_PARAM, param: name.slice(0, 48) };
    }
    seen.add(key);
    params.push({ name, hasValue: eq !== -1 });
  }
  return { ok: true, blocked: false, reason: REASON.OK, params, count: params.length };
}

module.exports = {
  REASON,
  DANGEROUS_KEYS,
  MAX_QUERY,
  evaluateQuery,
};
