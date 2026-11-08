'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  INCONSISTENT: 'inconsistent-mode',
};

const SITE_HEADER = 'sec-fetch-site';
const MODE_HEADER = 'sec-fetch-mode';
const DEST_HEADER = 'sec-fetch-dest';
const SITES = new Set(['same-origin', 'same-site', 'cross-site', 'none']);
const MODES = new Set(['cors', 'no-cors', 'navigate', 'same-origin', 'websocket']);
const DESTS = new Set([
  'audio',
  'audioworklet',
  'document',
  'embed',
  'empty',
  'font',
  'frame',
  'iframe',
  'image',
  'json',
  'manifest',
  'object',
  'paintworklet',
  'report',
  'script',
  'sharedworker',
  'style',
  'track',
  'video',
  'worker',
  'xslt',
]);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function textValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function applySecFetchSiteGuard(headers) {
  const key = headerKey(headers, SITE_HEADER);
  if (!key) return { changed: false, reason: REASON.MISSING };
  const site = textValue(headers, SITE_HEADER);
  if (!SITES.has(site)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const mode = textValue(headers, MODE_HEADER);
  if (mode && !MODES.has(mode)) {
    delete headers[headerKey(headers, MODE_HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const dest = textValue(headers, DEST_HEADER);
  if (dest && !DESTS.has(dest)) {
    delete headers[headerKey(headers, DEST_HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (site === 'none' && mode && mode !== 'navigate') {
    delete headers[key];
    return { changed: true, reason: REASON.INCONSISTENT };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applySecFetchSiteGuard };
