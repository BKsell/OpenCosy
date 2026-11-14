'use strict';

const MAX_TITLE_CHARS = 80;
const MAX_SUMMARY_CHARS = 140;
const MIN_HOVER_MS = 400;

const SENSITIVE_QUERY_KEYS = new Set([
  'token', 'access_token', 'auth', 'authorization', 'key', 'apikey', 'api_key',
  'password', 'passwd', 'pwd', 'secret', 'session', 'sessionid', 'sid', 'sig',
  'signature', 'code', 'otp'
]);

function truncate(text, limit) {
  if (typeof text !== 'string') return '';
  const value = text.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  if (value.length <= limit) return value;
  return value.slice(0, Math.max(0, limit - 1)) + '…';
}

function stripSensitiveQuery(url) {
  if (typeof url !== 'string') return '';
  const q = url.indexOf('?');
  if (q < 0) return { url, removed: 0 };
  const head = url.slice(0, q);
  const tail = url.slice(q + 1);
  const hashAt = tail.indexOf('#');
  const queryPart = hashAt >= 0 ? tail.slice(0, hashAt) : tail;
  const hashPart = hashAt >= 0 ? tail.slice(hashAt) : '';
  const kept = [];
  let removed = 0;
  for (const pair of queryPart.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const key = (eq >= 0 ? pair.slice(0, eq) : pair).toLowerCase();
    if (SENSITIVE_QUERY_KEYS.has(key)) {
      removed += 1;
      continue;
    }
    kept.push(pair);
  }
  const rebuilt = kept.length > 0 ? head + '?' + kept.join('&') : head;
  return { url: rebuilt + hashPart, removed };
}

function hostOf(url) {
  if (typeof url !== 'string') return '';
  const match = /^https?:\/\/([^/?#]+)/i.exec(url);
  if (!match) return '';
  return match[1].replace(/^[^@]*@/, '').toLowerCase();
}

function buildPreview(tab) {
  if (!tab || typeof tab !== 'object') return { ok: false, reason: 'malformed' };
  const rawUrl = typeof tab.url === 'string' ? tab.url : '';
  if (!/^https?:\/\//i.test(rawUrl)) return { ok: false, reason: 'bad-url' };
  const stripped = stripSensitiveQuery(rawUrl);
  const host = hostOf(rawUrl);
  if (!host) return { ok: false, reason: 'bad-url' };
  const title = truncate(tab.title, MAX_TITLE_CHARS) || host;
  return {
    ok: true,
    reason: 'ok',
    title,
    host,
    url: truncate(stripped.url, 512),
    removedParams: stripped.removed,
    summary: truncate(tab.summary, MAX_SUMMARY_CHARS),
    pinned: tab.pinned === true,
    muted: tab.muted === true,
    hasAudio: tab.hasAudio === true
  };
}

function shouldShowPreview(tab, hoverMs) {
  if (!tab || typeof tab !== 'object') return false;
  if (tab.dragging === true) return false;
  if (tab.isActive === true) return false;
  const elapsed = Number(hoverMs);
  if (!Number.isFinite(elapsed) || elapsed < MIN_HOVER_MS) return false;
  return /^https?:\/\//i.test(typeof tab.url === 'string' ? tab.url : '');
}

function previewBadges(preview) {
  if (!preview || preview.ok !== true) return [];
  const badges = [];
  if (preview.pinned) badges.push('已固定');
  if (preview.muted) badges.push('已静音');
  else if (preview.hasAudio) badges.push('正在发声');
  if (preview.removedParams > 0) badges.push('已隐藏敏感参数');
  return badges;
}

function renderPreviewText(preview) {
  if (!preview || preview.ok !== true) return '无预览';
  const badges = previewBadges(preview);
  const base = preview.title + ' — ' + preview.host;
  return badges.length > 0 ? base + ' [' + badges.join('|') + ']' : base;
}

module.exports = {
  MAX_TITLE_CHARS,
  MAX_SUMMARY_CHARS,
  MIN_HOVER_MS,
  stripSensitiveQuery,
  hostOf,
  buildPreview,
  shouldShowPreview,
  previewBadges,
  renderPreviewText
};
