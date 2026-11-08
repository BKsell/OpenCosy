'use strict';

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  SPOOFED: 'spoofed-entry',
  OVERLONG: 'overlong',
};

const HEADER = 'via';
const MAX_ENTRIES = 4;
const MAX_LENGTH = 512;
const ENTRY_RE = /^(?:\d\.\d\s+)?[a-z0-9.-]{1,64}(?::\d{1,5})?(?:\s+\([^()]{0,64}\))?$/i;

function applyViaGuard(headers) {
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
  const tokens = text.split(',');
  if (tokens.length > MAX_ENTRIES) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const kept = [];
  let dropped = false;
  for (const token of tokens) {
    const entry = token.trim();
    if (!entry) continue;
    if (entry.includes('internal') || entry.includes('proxy') && entry.includes('127.0.0.1')) {
      dropped = true;
      continue;
    }
    if (!ENTRY_RE.test(entry)) {
      dropped = true;
      continue;
    }
    kept.push(entry);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.SPOOFED };
  }
  if (dropped) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: REASON.SPOOFED };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyViaGuard };
