'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'filesystem-url-empty',
  NOT_FILESYSTEM: 'filesystem-url-not-filesystem',
  CREDENTIALS: 'filesystem-url-credentials',
  CROSS_ORIGIN: 'filesystem-url-cross-origin',
  TRAVERSAL: 'filesystem-url-traversal',
  NOT_PERSISTENT: 'filesystem-url-not-persistent',
};

function evaluateFilesystemUrl(url, options) {
  const opts = options || {};
  const text = typeof url === 'string' ? url.trim() : '';
  if (text === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  const prefix = 'filesystem:';
  if (!text.toLowerCase().startsWith(prefix)) {
    return { ok: false, blocked: true, reason: REASON.NOT_FILESYSTEM, url: text.slice(0, 48) };
  }
  const inner = text.slice(prefix.length);
  const match = /^(https?):\/\/([^/]+)(\/.*)?$/i.exec(inner);
  if (!match) {
    return { ok: false, blocked: true, reason: REASON.NOT_FILESYSTEM, url: text.slice(0, 64) };
  }
  const scheme = match[1].toLowerCase();
  const authority = match[2];
  const rest = match[3] || '/';
  if (authority.includes('@')) {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: text.slice(0, 64) };
  }
  if (scheme === 'http:') {
    return { ok: false, blocked: true, reason: REASON.CREDENTIALS, url: text.slice(0, 64) };
  }
  const origin = scheme + '://' + authority;
  if (opts.expectedOrigin && origin !== opts.expectedOrigin) {
    return { ok: false, blocked: true, reason: REASON.CROSS_ORIGIN, origin, expected: opts.expectedOrigin };
  }
  const decoded = decodeURIComponent(rest).toLowerCase();
  if (decoded.includes('..') || decoded.includes('%2e') || decoded.includes('/etc/') || decoded.includes('c:/')) {
    return { ok: false, blocked: true, reason: REASON.TRAVERSAL, path: rest.slice(0, 64) };
  }
  if (opts.persistent === true && !/^\/persistent\//.test(rest)) {
    return { ok: false, blocked: true, reason: REASON.NOT_PERSISTENT, path: rest.slice(0, 64) };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, path: rest };
}

function buildUrl(origin, type, path) {
  const base = String(origin || '');
  const kind = type === 'temporary' ? 'temporary' : 'persistent';
  const tail = String(path || '').startsWith('/') ? String(path) : '/' + String(path || '');
  return 'filesystem:' + base + '/' + kind + tail;
}

module.exports = {
  REASON,
  evaluateFilesystemUrl,
  buildUrl,
};
