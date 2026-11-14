"use strict";

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

module.exports = { single, originFromUrl, resetCooldown, splitList, stripControlChars, collapseSpaces, schemeOf, originOf, isObj, splitItems };
