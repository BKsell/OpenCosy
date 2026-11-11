'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed-challenge',
  BAD_SCHEME: 'invalid-scheme',
  CONTROL_CHAR: 'control-character',
  OVERLONG: 'overlong-value',
  BAD_REALM: 'malformed-realm',
  TOO_MANY: 'too-many-challenges',
};

const SCHEME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const QUOTED = /^"(?:[^"\\\x00-\x1f\x7f]|\\.)*"/;
const MAX_LENGTH = 1024;
const MAX_CHALLENGES = 4;

function hasControlChar(text) {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 9) continue;
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function parseChallenge(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MISSING };
  if (hasControlChar(text)) return { reason: REASON.CONTROL_CHAR };
  if (text.length > MAX_LENGTH) return { reason: REASON.OVERLONG };
  const space = text.indexOf(' ');
  const scheme = space === -1 ? text : text.slice(0, space);
  if (!SCHEME.test(scheme)) return { reason: REASON.BAD_SCHEME };
  const params = space === -1 ? '' : text.slice(space + 1).trim();
  const params2 = [];
  let cursor = 0;
  while (cursor < params.length) {
    while (cursor < params.length && (params[cursor] === ',' || params[cursor] === ' ')) cursor += 1;
    if (cursor >= params.length) break;
    const eq = params.indexOf('=', cursor);
    if (eq === -1) return { reason: REASON.MALFORMED };
    const key = params.slice(cursor, eq).trim();
    if (!SCHEME.test(key)) return { reason: REASON.MALFORMED };
    let end = eq + 1;
    let rawValue = '';
    if (params[end] === '"') {
      const match = QUOTED.exec(params.slice(end));
      if (!match) return { reason: REASON.BAD_REALM };
      rawValue = match[0];
      end += rawValue.length;
      if (end < params.length && params[end] !== ',') return { reason: REASON.MALFORMED };
    } else {
      while (end < params.length && params[end] !== ',') end += 1;
      rawValue = params.slice(eq + 1, end).trim();
      if (!rawValue) return { reason: REASON.MALFORMED };
    }
    params2.push({ key: key.toLowerCase(), value: rawValue });
    cursor = end;
  }
  return { reason: REASON.OK, scheme: scheme.toLowerCase(), params: params2 };
}

module.exports = { REASON, SCHEME, QUOTED, MAX_LENGTH, MAX_CHALLENGES, hasControlChar, parseChallenge };
