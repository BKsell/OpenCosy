'use strict';

const REASON = {
  OK: 'ok',
  EMPTY: 'share-empty',
  INSECURE: 'share-insecure',
  SECRET_IN_URL: 'share-secret-url',
  OVERSIZED_FILE: 'share-oversized-file',
  BAD_FILE_TYPE: 'share-bad-file-type',
  NO_TITLE_URL: 'share-no-title-url',
};

const MAX_FILE = 64 * 1024 * 1024;
const BAD_TYPES = ['application/x-executable', 'application/x-msdownload', 'application/javascript', 'text/html'];

function evaluateShare(payload, options) {
  const opts = options || {};
  const data = payload || {};
  const origin = typeof data.origin === 'string' ? data.origin.trim() : '';
  if (origin === '') return { ok: false, blocked: true, reason: REASON.EMPTY };
  if (!origin.toLowerCase().startsWith('https://')) {
    return { ok: false, blocked: true, reason: REASON.INSECURE, origin: origin.slice(0, 48) };
  }
  if (data.title === undefined && data.text === undefined && data.url === undefined && !Array.isArray(data.files)) {
    return { ok: false, blocked: true, reason: REASON.EMPTY, origin };
  }
  if (typeof data.url === 'string' && data.url !== '') {
    let parsed;
    try {
      parsed = new URL(data.url);
    } catch (err) {
      return { ok: false, blocked: true, reason: REASON.SECRET_IN_URL, url: data.url.slice(0, 48) };
    }
    if (parsed.username || parsed.password) {
      return { ok: false, blocked: true, reason: REASON.SECRET_IN_URL, url: parsed.origin };
    }
    if (parsed.protocol !== 'https:' && opts.allowHttp !== true) {
      return { ok: false, blocked: true, reason: REASON.INSECURE, url: parsed.href.slice(0, 48) };
    }
    const hash = parsed.hash.toLowerCase();
    if (hash.includes('token=') || hash.includes('access_token') || hash.includes('code=')) {
      return { ok: false, blocked: true, reason: REASON.SECRET_IN_URL, url: parsed.origin + parsed.pathname };
    }
  }
  const files = Array.isArray(data.files) ? data.files : [];
  for (const file of files) {
    const size = Number(file && file.size);
    if (Number.isFinite(size) && size > MAX_FILE) {
      return { ok: false, blocked: true, reason: REASON.OVERSIZED_FILE, size };
    }
    const type = String(file && file.type || '').toLowerCase();
    if (BAD_TYPES.includes(type)) {
      return { ok: false, blocked: true, reason: REASON.BAD_FILE_TYPE, type };
    }
  }
  if ((data.title || data.text) && !data.url && files.length === 0) {
    return { ok: false, blocked: false, reason: REASON.NO_TITLE_URL, origin };
  }
  return { ok: true, blocked: false, reason: REASON.OK, origin, files: files.length };
}

function sanitizeText(text, limit) {
  const max = typeof limit === 'number' && limit > 0 ? limit : 256;
  const value = typeof text === 'string' ? text : '';
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);
}

module.exports = {
  REASON,
  MAX_FILE,
  BAD_TYPES,
  evaluateShare,
  sanitizeText,
};
