"use strict";

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

module.exports = { tokensOf, containsControlChar, hasControlChar, fallbackTitleFor, hasControlCharV2, hasControlCharV3, asBytes, listValues, normalizeCharset, safeInt, safeIntV2, isPlainObject, httpOrigin, resetRateWindow, inCooldown, isHttpUrl };
