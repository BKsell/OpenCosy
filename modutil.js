"use strict";

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
  return String(s).replace(/[\u0000-\u001F\u007F]/g, '');
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

function hasControlChars(value) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function parseUrl(raw) {
  if (typeof raw !== 'string' || raw === '') return null;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function safeParse(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function hasControlCharsV2(text) {
  for (const ch of text) {
    const code = ch.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

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

function containsControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
    if (c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

function hasControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
  }
  return false;
}

function fallbackTitleFor(u) {
  try {
    return u.hostname.replace(/^www\./i, '') || u.href;
  } catch {
    return u.href;
  }
}

function hasControlCharV2(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code <= 0x1F || code === 0x7F) return true;
  }
  return false;
}

function hasControlCharV3(s) {
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
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

module.exports = {
  pruneOlderThan,
  singleAlt,
  countSince,
  single,
  originFromUrl,
  httpOrigin,
  resetCooldown,
  resetRateWindow,
  inCooldown,
  isHttpUrl,
  splitList,
  stripControlChars,
  collapseSpaces,
  schemeOf,
  originOf,
  isObj,
  splitItems,
  hasControlChars,
  parseUrl,
  safeParse,
  hasControlCharsV2,
  headerValues,
  tokensOf,
  containsControlChar,
  hasControlChar,
  fallbackTitleFor,
  hasControlCharV2,
  hasControlCharV3,
  asBytes,
  listValues,
  normalizeCharset,
  safeInt,
  safeIntV2,
  isPlainObject,
};
