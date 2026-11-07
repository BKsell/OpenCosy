'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'blob-url-empty',
  NOT_BLOB: 'blob-url-not-blob',
  OPAQUE_ORIGIN: 'blob-url-opaque-origin',
  CROSS_ORIGIN: 'blob-url-cross-origin',
  CREDENTIALS: 'blob-url-credentials',
  NESTED: 'blob-url-nested',
};

function evaluateBlobUrl(url, options) {
  const opts = options || {};
  const text = typeof url === 'string' ? url.trim() : '';
  if (text === '') {
    return { ok: false, blocked: true, reason: REASON.EMPTY };
  }
  const prefix = 'blob:';
  if (!text.toLowerCase().startsWith(prefix)) {
    return { ok: false, blocked: true, reason: REASON.NOT_BLOB, url: text.slice(0, 48) };
  }
  const inner = text.slice(prefix.length);
  if (inner.toLowerCase().startsWith(prefix)) {
    return { ok: false, blocked: true, reason: REASON.NESTED, url: text.slice(0, 64) };
  }
  if (inner.toLowerCase().startsWith('null')) {
    return { ok: false, blocked: true, reason: REASON.OPAQUE_ORIGIN, url: text.slice(0, 64) };
  }
  let origin;
  try {
    origin = new URL(inner).origin;
  } catch (err) {
    return { ok: false, blocked: true, reason: REASON.OPAQUE_ORIGIN, url: text.slice(0, 64) };
  }
  if (origin === 'null' || origin === '') {
    return { ok: false, blocked: true, reason: REASON.OPAQUE_ORIGIN, url: text.slice(0, 64) };
  }
  const parsed = new URL(inner);
  if (parsed.username || parsed.password) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: parsed.origin };
  }
  if (opts.expectedOrigin && parsed.origin !== opts.expectedOrigin) {
    return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, origin: parsed.origin, expected: opts.expectedOrigin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin: parsed.origin, mime: parsed.pathname.replace(/^\//, '') };
}

function revokeAll(created) {
  const list = Array.isArray(created) ? created : [];
  const revoked = [];
  for (const url of list) {
    const result = evaluateBlobUrl(url);
    if (result.ok) revoked.push(url);
  }
  return { requested: list.length, revoked: revoked.length };
}

module.exports = {
  REASON,
  evaluateBlobUrl,
  revokeAll,
};
