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

function sanitizeDisplayTitle(rawTitle, maxChars) {
  let t = typeof rawTitle === 'string' ? rawTitle : '';
  t = t.replace(/[\t\n\r]+/g, ' ');
  t = collapseSpaces(stripControlChars(t));
  if (t.length > maxChars) t = t.slice(0, maxChars);
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

module.exports = Object.assign({}, require('./modutil_part2'), {
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
