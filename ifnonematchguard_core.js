'use strict';

const { firstValue, headerKey } = require('./headerutil_core');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_TAG: 'bad-tag',
  OVERLONG: 'overlong',
};

const HEADER = 'if-none-match';
const MAX_LENGTH = 1024;
const MAX_TAGS = 16;
const ETAG_RE = /^(?:W\/)?"[\u0021-\u007e]{1,128}"$/;

function applyIfNoneMatchGuard(headers) {
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
  if (tokens.length > MAX_TAGS) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.OVERLONG };
  }
  const kept = [];
  let dropped = false;
  for (const token of tokens) {
    const tag = token.trim();
    if (!tag) continue;
    if (tag === '*') {
      kept.push('*');
      continue;
    }
    if (!ETAG_RE.test(tag)) {
      dropped = true;
      continue;
    }
    kept.push(tag);
  }
  if (kept.length === 0) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_TAG };
  }
  if (dropped) {
    headers[headerKey(headers, HEADER)] = kept.join(', ');
    return { changed: true, reason: REASON.BAD_TAG };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyIfNoneMatchGuard };
