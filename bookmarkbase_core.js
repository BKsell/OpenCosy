'use strict';

const MAX_BOOKMARKS_IMPORT = 5000;
const MAX_URL_LENGTH = 4096;
const MAX_TITLE_LENGTH = 500;
const MAX_IMPORT_FILE_BYTES = 8 * 1024 * 1024; // 8MiB，正常书签文件远小于此

function safeBookmarkURL(raw) {
  if (typeof raw !== 'string') return null;
  const s = raw.trim();
  if (!s || s.length > MAX_URL_LENGTH) return null;
  let u;
  try {
    u = new URL(s);
  } catch (_) {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  // 忽略凭据片段，书签里带 userinfo 几乎一定是误导出或钓鱼。
  if (u.username || u.password) return null;
  return u.toString();
}

function cleanTitle(raw) {
  const t = (typeof raw === 'string' ? raw : '').replace(/\s+/g, ' ').trim();
  return t.slice(0, MAX_TITLE_LENGTH);
}

function normalizeBookmark(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
  const url = safeBookmarkURL(item.url);
  if (!url) return null;
  const title = cleanTitle(item.title) || url;
  let addedDate = null;
  if (typeof item.addedDate === 'string') {
    const ts = Date.parse(item.addedDate);
    if (Number.isFinite(ts)) addedDate = new Date(ts).toISOString();
  }
  return { url, title, addedDate };
}

function stripTags(s) {
  return String(s).replace(/<[^>]*>/g, '');
}

function decodeHTMLEntities(s) {
  return String(s)
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&nbsp;/gi, ' ');
}

function escapeHTML(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

module.exports = {
  MAX_BOOKMARKS_IMPORT,
  MAX_URL_LENGTH,
  MAX_TITLE_LENGTH,
  MAX_IMPORT_FILE_BYTES,
  safeBookmarkURL,
  cleanTitle,
  normalizeBookmark,
  stripTags,
  decodeHTMLEntities,
  escapeHTML,
};
