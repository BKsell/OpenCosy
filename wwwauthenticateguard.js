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

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

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

function inspectAuthenticate(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return { present: false, key: '', challenges: [], reason: REASON.MISSING };
  const raw = headers[key];
  const list = Array.isArray(raw) ? raw : [raw];
  if (list.length > MAX_CHALLENGES) {
    return { present: true, key, challenges: [], reason: REASON.TOO_MANY };
  }
  const challenges = list.map(parseChallenge);
  const bad = challenges.find((item) => item.reason !== REASON.OK);
  return {
    present: true,
    key,
    challenges,
    reason: bad ? bad.reason : REASON.OK,
  };
}

function applyWwwAuthenticateGuard(headers, name) {
  const result = inspectAuthenticate(headers, name);
  if (!result.present) return { changed: false, reason: REASON.MISSING, challenges: 0 };
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, challenges: result.challenges.length };
  }
  delete headers[result.key];
  return { changed: true, reason: result.reason, challenges: 0 };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MISSING:
      return '未声明认证挑战';
    case REASON.MALFORMED:
      return '认证挑战参数无法解析，已移除';
    case REASON.BAD_SCHEME:
      return '认证方案名非法，已移除';
    case REASON.CONTROL_CHAR:
      return '认证挑战含控制字符，已移除';
    case REASON.OVERLONG:
      return '认证挑战超长，已移除';
    case REASON.BAD_REALM:
      return 'realm 引号不完整，已移除';
    case REASON.TOO_MANY:
      return '认证挑战数量超限，已移除';
    default:
      return '认证挑战通过校验';
  }
}

module.exports = {
  REASON,
  MAX_LENGTH,
  MAX_CHALLENGES,
  parseChallenge,
  inspectAuthenticate,
  applyWwwAuthenticateGuard,
  describeReason,
};
