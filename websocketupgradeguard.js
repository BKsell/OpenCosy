'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'ws-handshake-empty',
  BAD_KEY: 'ws-handshake-bad-key',
  BAD_VERSION: 'ws-handshake-bad-version',
  ORIGIN_MISMATCH: 'ws-handshake-origin',
  CREDENTIALS: 'ws-handshake-credentials',
  PLAINTEXT: 'ws-handshake-plaintext',
  IMMUTABLE_VIOLATION: 'ws-handshake-immutable',
};

const WS_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const PROTOCOLS = ['ws:', 'wss:'];

function headerValue(headers, name) {
  const list = Array.isArray(headers) ? headers : [];
  for (const entry of list) {
    if (!Array.isArray(entry)) continue;
    if (String(entry[0] || '').toLowerCase() === name) return String(entry[1] || '');
  }
  return null;
}

function evaluateHandshake(request, options) {
  const opts = options || {};
  const req = request || {};
  const url = typeof req.url === 'string' ? req.url.trim() : '';
  if (url === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, url: url.slice(0, 48) };
  }
  if (!PROTOCOLS.includes(parsed.protocol)) {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, protocol: parsed.protocol };
  }
  if (parsed.username || parsed.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, origin: parsed.origin };
  }
  if (opts.secureOnly !== false && parsed.protocol === 'ws:') {
    return { ok: false, blocked: true, reason: REASON.PLAINTEXT, protocol: 'ws:' };
  }
  const headers = Array.isArray(req.headers) ? req.headers : [];
  const key = headerValue(headers, 'sec-websocket-key');
  if (key === null || !/^[A-Za-z0-9+/]{22}==$/.test(key.trim())) {
    return { ok: false, blocked: true, reason: REASON.BAD_KEY, key: String(key || '').slice(0, 16) };
  }
  const version = headerValue(headers, 'sec-websocket-version');
  if (version === null || version.trim() !== '13') {
    return { ok: false, blocked: true, reason: REASON.BAD_VERSION, version: String(version || '').slice(0, 8) };
  }
  const origin = headerValue(headers, 'origin');
  if (origin === null || origin.trim() === '') {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_MISMATCH };
  }
  if (opts.expectedOrigin && origin.trim().toLowerCase() !== opts.expectedOrigin.toLowerCase()) {
    return { ok: false, blocked: true, reason: REASON.ORIGIN_MISMATCH, origin: origin.trim().slice(0, 48) };
  }
  const extensions = headerValue(headers, 'sec-websocket-extensions');
  if (extensions && extensions.includes('permessage-deflate') && opts.allowCompression !== true) {
    return { ok: false, blocked: false, reason: REASON.IMMUTABLE_VIOLATION, extensions: extensions.slice(0, 48) };
  }
  return { ok: true, blocked: false, reason: REASON.OK, protocol: parsed.protocol, keyLength: key.trim().length };
}

function describe(result) {
  if (!result || result.ok) return 'websocket handshake accepted';
  return result.reason + ' (' + String(result.key || result.origin || result.protocol || '') + ')';
}

module.exports = {
  REASON,
  WS_MAGIC,
  evaluateHandshake,
  describe,
};
