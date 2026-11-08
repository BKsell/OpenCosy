'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  DUPLICATE: 'duplicate',
  TOO_MANY: 'too-many',
  UNSAFE_CHARS: 'unsafe-chars',
};

const ACCEPT_HEADER = 'sec-websocket-accept';
const PROTOCOL_HEADER = 'sec-websocket-protocol';
const MAX_ACCEPT_LENGTH = 28;
const MAX_PROTOCOL_LENGTH = 64;
const MAX_PROTOCOLS = 4;

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

function hasControlChars(text) {
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function inspectAccept(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (hasControlChars(text)) return { reason: REASON.UNSAFE_CHARS };
  if (text.length > MAX_ACCEPT_LENGTH) return { reason: REASON.OVERLONG };
  if (!/^[A-Za-z0-9+/]{27}=$/.test(text)) return { reason: REASON.MALFORMED };
  return { reason: REASON.OK };
}

function inspectProtocols(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, protocols: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, protocols: [] };
  const seen = new Set();
  const protocols = [];
  let reason = REASON.OK;
  for (const raw of text.split(',')) {
    const protocol = raw.trim();
    if (!protocol) continue;
    if (protocol.length > MAX_PROTOCOL_LENGTH) {
      if (reason === REASON.OK) reason = REASON.OVERLONG;
      continue;
    }
    if (hasControlChars(protocol)) {
      if (reason === REASON.OK) reason = REASON.UNSAFE_CHARS;
      continue;
    }
    if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(protocol)) {
      if (reason === REASON.OK) reason = REASON.MALFORMED;
      continue;
    }
    const lower = protocol.toLowerCase();
    if (seen.has(lower)) {
      if (reason === REASON.OK) reason = REASON.DUPLICATE;
      continue;
    }
    if (protocols.length >= MAX_PROTOCOLS) {
      if (reason === REASON.OK) reason = REASON.TOO_MANY;
      continue;
    }
    seen.add(lower);
    protocols.push(protocol);
  }
  if (protocols.length === 0 && reason === REASON.OK) reason = REASON.MALFORMED;
  return { reason, protocols };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'websocket 握手头合规';
    case REASON.MISSING:
      return '响应未声明 websocket 握手头';
    case REASON.MALFORMED:
      return 'websocket 握手头取值非法，已剥除';
    case REASON.OVERLONG:
      return 'websocket 握手头超长，已剥除';
    case REASON.DUPLICATE:
      return 'websocket 子协议重复，已去重';
    case REASON.TOO_MANY:
      return 'websocket 子协议过多，已截断';
    case REASON.UNSAFE_CHARS:
      return 'websocket 握手头含控制字符，已剥除';
    default:
      return 'websocket 握手头未识别状态';
  }
}

function applySecWebSocketAcceptGuard(headers) {
  const value = firstValue(headers, ACCEPT_HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectAccept(value);
  const findings = [{ reason: result.reason }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  deleteHeader(headers, ACCEPT_HEADER);
  return { changed: true, reason: result.reason, findings };
}

function applySecWebSocketProtocolGuard(headers) {
  const value = firstValue(headers, PROTOCOL_HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, findings: [] };
  const result = inspectProtocols(value);
  const findings = [{ reason: result.reason, protocols: result.protocols }];
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, findings };
  }
  if (result.protocols.length === 0) {
    deleteHeader(headers, PROTOCOL_HEADER);
  } else {
    headers[headerKey(headers, PROTOCOL_HEADER)] = [result.protocols.join(', ')];
  }
  return { changed: true, reason: result.reason, findings };
}

module.exports = {
  REASON,
  ACCEPT_HEADER,
  PROTOCOL_HEADER,
  inspectAccept,
  inspectProtocols,
  applySecWebSocketAcceptGuard,
  applySecWebSocketProtocolGuard,
  describeReason,
};
