'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  WEAK_ALGORITHM: 'weak-algorithm',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  DUPLICATE_MEMBER: 'duplicate-member',
  TOO_MANY: 'too-many',
  EMPTY: 'empty',
};

const HEADERS = ['content-digest', 'repr-digest'];
const MAX_VALUE_LENGTH = 1024;
const MAX_MEMBERS = 8;
const ALGORITHMS = {
  'sha-256': 32,
  'sha-512': 64,
};
const WEAK_ALGORITHMS = new Set(['md5', 'sha', 'sha-1']);

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

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function splitMembers(text) {
  const members = [];
  let current = '';
  let inByteSequence = false;
  for (const ch of text) {
    if (ch === ':' && !inByteSequence) {
      inByteSequence = true;
      current += ch;
      continue;
    }
    if (ch === ':' && inByteSequence) {
      inByteSequence = false;
      current += ch;
      continue;
    }
    if (ch === ',' && !inByteSequence) {
      members.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) members.push(current.trim());
  return members;
}

function parseMember(token) {
  const text = token.trim();
  if (!text) return null;
  const eq = text.indexOf('=');
  if (eq <= 0) return { algorithm: text.toLowerCase(), valid: false };
  const algorithm = text.slice(0, eq).trim().toLowerCase();
  let value = text.slice(eq + 1).trim();
  if (!algorithm) return null;
  if (!value.startsWith(':') || !value.endsWith(':') || value.length < 3) {
    return { algorithm, valid: false };
  }
  value = value.slice(1, -1);
  const expected = ALGORITHMS[algorithm];
  if (!expected) {
    return { algorithm, valid: false, unsupported: !WEAK_ALGORITHMS.has(algorithm) };
  }
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length !== expected) return { algorithm, valid: false };
  const canonical = buffer.toString('base64');
  if (canonical !== value) return { algorithm, valid: false };
  return { algorithm, valid: true, token: `${algorithm}=:${value}:` };
}

function inspectDigest(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, members: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.EMPTY, members: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, members: [] };
  const seen = new Set();
  const members = [];
  let reason = REASON.OK;
  for (const token of splitMembers(text)) {
    const member = parseMember(token);
    if (!member) continue;
    if (WEAK_ALGORITHMS.has(member.algorithm) && !member.valid) {
      if (reason === REASON.OK) reason = REASON.WEAK_ALGORITHM;
      continue;
    }
    if (!member.valid) {
      if (reason === REASON.OK) reason = member.unsupported ? REASON.UNSUPPORTED_ALGORITHM : REASON.MALFORMED;
      continue;
    }
    if (seen.has(member.algorithm)) {
      if (reason === REASON.OK) reason = REASON.DUPLICATE_MEMBER;
      continue;
    }
    seen.add(member.algorithm);
    if (members.length >= MAX_MEMBERS) {
      if (reason === REASON.OK) reason = REASON.TOO_MANY;
      continue;
    }
    members.push(member.token);
  }
  if (members.length === 0 && reason === REASON.OK) reason = REASON.MALFORMED;
  return { reason, members };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return '摘要头合规';
    case REASON.MISSING:
      return '响应未声明摘要头';
    case REASON.MALFORMED:
      return '摘要头取值非法，已剥除';
    case REASON.OVERLONG:
      return '摘要头超长，已剥除';
    case REASON.WEAK_ALGORITHM:
      return '摘要使用弱算法，已剥除';
    case REASON.UNSUPPORTED_ALGORITHM:
      return '摘要使用不支持的算法，已剥除';
    case REASON.DUPLICATE_MEMBER:
      return '摘要重复算法成员，已去重';
    case REASON.TOO_MANY:
      return '摘要成员过多，已截断';
    case REASON.EMPTY:
      return '摘要头为空，已剥除';
    default:
      return '摘要头未识别状态';
  }
}

function applyDigestGuard(headers, name) {
  const header = name || 'content-digest';
  const value = firstValue(headers, header);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectDigest(value);
  const findings = [{ reason: result.reason, members: result.members }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (result.members.length === 0) {
    deleteHeader(headers, header);
  } else {
    headers[headerKey(headers, header)] = [result.members.join(', ')];
  }
  return { changed: true, reason: result.reason, findings };
}

function applyContentDigestGuard(headers) {
  return applyDigestGuard(headers, 'content-digest');
}

function applyReprDigestGuard(headers) {
  return applyDigestGuard(headers, 'repr-digest');
}

module.exports = {
  REASON,
  HEADERS,
  inspectDigest,
  applyDigestGuard,
  applyContentDigestGuard,
  applyReprDigestGuard,
  describeReason,
};
