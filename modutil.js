"use strict";

const { hasAsciiControlChar, hasUnicodeControlChar, parseUrl } = require('./modutilctrl');
function pruneOlderThan(list, cutoff) {
  let i = 0;
  while (i < list.length && list[i] < cutoff) i++;
  if (i > 0) list.splice(0, i);
}

function singleAlt(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  return headers[key];
}

function countSince(sortedTimes, cutoff) {
  let n = 0;
  for (let i = sortedTimes.length - 1; i >= 0; i--) {
    if (sortedTimes[i] >= cutoff) n++;
    else break;
  }
  return n;
}

function single(raw) {
  if (Array.isArray(raw)) {
    if (raw.length !== 1) return null;
    return String(raw[0]).trim();
  }
  if (typeof raw !== 'string') return null;
  return raw.trim();
}

function originFromUrl(rawUrl) {
  try {
    return new URL(rawUrl || '').origin;
  } catch {
    return '';
  }
}

function resetCooldown(state) {
  if (state) state.cooldownUntil = 0;
}

function splitList(raw) {
  if (Array.isArray(raw)) return raw.map((v) => String(v)).join(',').split(',');
  if (typeof raw !== 'string') return [];
  return raw.split(',');
}

function stripControlChars(s) {
  return String(s).replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g, '');
}

function collapseSpaces(s) {
  return s.replace(/\s+/g, ' ').trim();
}

function schemeOf(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  const m = /^([a-z][a-z0-9+.-]*:)/i.exec(rawUrl.trim());
  return m ? m[1].toLowerCase() : '';
}

function originOf(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function isObj(v) {
  return v !== null && typeof v === 'object';
}

function splitItems(text) {
  const items = [];
  let current = '';
  let inQuote = false;
  for (const ch of text) {
    if (ch === '"') inQuote = !inQuote;
    if (ch === ',' && !inQuote) {
      items.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) items.push(current);
  return items;
}

const hasControlChars = hasAsciiControlChar;
const hasControlCharsV2 = hasAsciiControlChar;
const hasControlCharV2 = hasAsciiControlChar;
const hasControlCharV3 = hasAsciiControlChar;
const containsControlChar = hasUnicodeControlChar;
const hasControlChar = hasUnicodeControlChar;

const safeParse = parseUrl;

function headerValues(headers, name) {
  const target = String(name || '').toLowerCase();
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() !== target) continue;
    const value = headers[key];
    if (Array.isArray(value)) return value.slice();
    if (typeof value === 'string') return [value];
  }
  return [];
}

function sanitizeDisplayTitle(rawTitle, maxChars) {
  let t = typeof rawTitle === 'string' ? rawTitle : '';
  t = t.replace(/[\t\n\r]+/g, ' ');
  t = collapseSpaces(stripControlChars(t));
  if (t.length > maxChars) {
    t = t.slice(0, maxChars);
    const last = t.charCodeAt(t.length - 1);
    if (last >= 0xd800 && last <= 0xdbff) t = t.slice(0, -1);
  }
  return t;
}

function readStoredSection(readStore, path, pick, label) {
  try {
    const data = readStore(path, null);
    if (!data || typeof data !== 'object') return [];
    return pick(data);
  } catch (e) {
    console.error(label, e);
    return [];
  }
}

function tokensOf(values) {
  const out = [];
  for (const value of values) {
    for (const token of String(value).split(',')) {
      const trimmed = token.trim();
      if (trimmed) out.push(trimmed);
    }
  }
  return out;
}

function fallbackTitleFor(u) {
  try {
    return u.hostname.replace(/^www\./i, '') || u.href;
  } catch {
    return u.href;
  }
}

function asBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return 0;
  }
  return Math.floor(n);
}

function listValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return [];
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.filter((item) => typeof item === 'string');
  return typeof raw === 'string' ? [raw] : [];
}

function normalizeCharset(token) {
  const text = token.trim().toLowerCase();
  if (!text) return '';
  const semi = text.indexOf(';');
  return (semi >= 0 ? text.slice(0, semi) : text).trim();
}

function safeInt(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return null;
  if (!Number.isInteger(value)) return null;
  return value;
}

function safeIntV2(value, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.trunc(n);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function httpOrigin(rawUrl) {
  if (typeof rawUrl !== 'string' || !rawUrl) return '';
  try {
    const u = new URL(rawUrl);
    if (u.protocol === 'http:' || u.protocol === 'https:') {
      return u.origin === 'null' ? '' : u.origin;
    }
    return '';
  } catch {
    return '';
  }
}

function resetRateWindow(st) {
  if (!st) return;
  st.burstStart = -1;
  st.burstCount = 0;
  st.longStart = -1;
  st.longCount = 0;
  st.cooldownUntil = 0;
}

function inCooldown(state, now) {
  return !!state && state.cooldownUntil > now;
}

function isHttpUrl(url) {
  return typeof url === 'string'
    && (url.startsWith('http://') || url.startsWith('https://'));
}

module.exports = Object.assign({}, { tokensOf, containsControlChar, hasControlChar, fallbackTitleFor, hasControlCharV2, hasControlCharV3, asBytes, listValues, normalizeCharset, safeInt, safeIntV2, isPlainObject, httpOrigin, resetRateWindow, inCooldown, isHttpUrl }, {
  pruneOlderThan,
  singleAlt,
  countSince,
  single,
  originFromUrl,
  resetCooldown,
  splitList,
  stripControlChars,
  collapseSpaces,
  sanitizeDisplayTitle,
  readStoredSection,
  schemeOf,
  originOf,
  isObj,
  splitItems,
  hasControlChars,
  parseUrl,
  safeParse,
  hasControlCharsV2,
  headerValues,
});
