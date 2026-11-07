'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  HOP_BY_HOP: 'hop-by-hop',
  CONNECTION_TOKEN: 'connection-token',
  OVERLONG: 'overlong',
};

const MAX_CONNECTION_LENGTH = 200;
const HOP_HEADERS = [
  'proxy-connection',
  'keep-alive',
  'te',
  'trailer',
  'upgrade',
  'proxy-authenticate',
  'proxy-authentication-info',
  'proxy-authorization',
];
const HOP_SET = new Set(HOP_HEADERS);
const CONNECTION_STOPWORDS = new Set(['close', 'keep-alive']);

function lowerKeys(headers) {
  const map = {};
  if (!headers || typeof headers !== 'object') return map;
  for (const key of Object.keys(headers)) map[key.toLowerCase()] = key;
  return map;
}

function firstHeader(headers, name) {
  const keys = lowerKeys(headers);
  const key = keys[name];
  if (!key) return { key: '', value: '' };
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw.join(', ') : raw;
  return { key, value: typeof value === 'string' ? value : '' };
}

function parseConnectionTokens(value) {
  if (typeof value !== 'string') return [];
  const tokens = value.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  return tokens.filter((t) => !CONNECTION_STOPWORDS.has(t));
}

function inspectHopByHop(headers) {
  const keys = lowerKeys(headers);
  if (!headers || typeof headers !== 'object' || Object.keys(headers).length === 0) {
    return { changed: false, reason: REASON.MISSING, stripped: [] };
  }
  const stripped = [];
  let reason = REASON.MISSING;
  for (const name of HOP_HEADERS) {
    if (keys[name]) {
      delete headers[keys[name]];
      stripped.push(name);
      reason = REASON.HOP_BY_HOP;
    }
  }
  const connection = firstHeader(headers, 'connection');
  if (connection.value) {
    if (connection.value.length > MAX_CONNECTION_LENGTH) {
      delete headers[connection.key];
      stripped.push('connection');
      reason = REASON.OVERLONG;
    } else {
      const tokens = parseConnectionTokens(connection.value);
      for (const token of tokens) {
        const key = keys[token];
        if (key && key !== connection.key && !HOP_SET.has(token)) {
          delete headers[key];
          stripped.push(token);
          reason = REASON.CONNECTION_TOKEN;
        }
      }
      if (tokens.length) {
        delete headers[connection.key];
        stripped.push('connection');
        if (reason === REASON.MISSING) reason = REASON.CONNECTION_TOKEN;
      }
    }
  }
  if (!stripped.length) return { changed: false, reason: REASON.OK, stripped: [] };
  return { changed: true, reason, stripped };
}

function applyHopByHopGuard(headers) {
  return inspectHopByHop(headers);
}

function describeReason(reason) {
  switch (reason) {
    case REASON.HOP_BY_HOP:
      return '剥离了逐跳响应头';
    case REASON.CONNECTION_TOKEN:
      return '剥离了 Connection 声明的逐跳头';
    case REASON.OVERLONG:
      return 'Connection 头超长';
    default:
      return '响应头通过逐跳校验';
  }
}

module.exports = {
  REASON,
  MAX_CONNECTION_LENGTH,
  HOP_HEADERS,
  parseConnectionTokens,
  inspectHopByHop,
  applyHopByHopGuard,
  describeReason,
};
