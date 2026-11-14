'use strict';

const { firstValue, headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_TOKEN: 'bad-token',
  HOP_BY_HOP_LEAK: 'hop-by-hop-leak',
};

const HEADER = 'connection';
const PROTECTED = new Set([
  'host',
  'content-length',
  'authorization',
  'cookie',
  'set-cookie',
  'transfer-encoding',
  'content-type',
  'origin',
]);
const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

function applyConnectionGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim().toLowerCase();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  const tokens = text.split(',').map((token) => token.trim()).filter(Boolean);
  const kept = [];
  let badToken = false;
  let leaked = false;
  for (const token of tokens) {
    if (!TOKEN_RE.test(token)) {
      badToken = true;
      continue;
    }
    if (PROTECTED.has(token)) {
      leaked = true;
      continue;
    }
    if (token === 'close' || token === 'keep-alive' || token === 'upgrade' || token === 'te') {
      kept.push(token);
    } else {
      kept.push(token);
    }
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: leaked ? REASON.HOP_BY_HOP_LEAK : REASON.BAD_TOKEN };
  }
  if (badToken || leaked) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: leaked ? REASON.HOP_BY_HOP_LEAK : REASON.BAD_TOKEN };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyConnectionGuard };
