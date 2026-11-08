'use strict';

const MAX_NAME_BYTES = 240;
const FALLBACK_NAME = 'download';

const FORBIDDEN_ASCII = new Set(['<', '>', ':', '"', '/', '\\', '|', '?', '*']);
const RESERVED_DEVICE = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

function isInvisibleCodePoint(cp) {
  if (cp >= 0x200b && cp <= 0x200f) return true;
  if (cp >= 0x202a && cp <= 0x202e) return true;
  if (cp >= 0x2066 && cp <= 0x2069) return true;
  if (cp === 0xfeff) return true;
  if (cp >= 0xe0000 && cp <= 0xe007f) return true;
  return false;
}

function stripControlAndInvisible(raw) {
  let out = '';
  for (const ch of raw) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x1f || cp === 0x7f) continue;
    if (isInvisibleCodePoint(cp)) continue;
    out += ch;
  }
  return out;
}

function stripPathComponents(raw) {
  let s = raw;
  const cut = Math.max(s.lastIndexOf('/'), s.lastIndexOf('\\'));
  if (cut >= 0) s = s.slice(cut + 1);
  return s;
}

function stripTrailingDotsAndSpaces(raw) {
  let s = raw;
  while (s.length > 0) {
    const last = s[s.length - 1];
    if (last === '.' || last === ' ' || last === '\t') {
      s = s.slice(0, -1);
      continue;
    }
    break;
  }
  return s;
}

function splitStemExt(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return { stem: name, ext: '' };
  return { stem: name.slice(0, dot), ext: name.slice(dot) };
}

function prefixReservedDevice(name) {
  const { stem } = splitStemExt(name);
  const upper = stem.toUpperCase();
  if (!RESERVED_DEVICE.has(upper)) return name;
  return '_' + name;
}

function byteLength(s) {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp <= 0x7f) n += 1;
    else if (cp <= 0x7ff) n += 2;
    else if (cp <= 0xffff) n += 3;
    else n += 4;
  }
  return n;
}

function truncateToBytes(name, limit) {
  if (byteLength(name) <= limit) return name;
  const { stem, ext } = splitStemExt(name);
  const extBytes = byteLength(ext);
  if (extBytes >= limit - 8) {
    const out = [];
    let used = 0;
    for (const ch of name) {
      const cp = ch.codePointAt(0);
      const w = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
      if (used + w > limit) break;
      out.push(ch);
      used += w;
    }
    return out.join('');
  }
  const budget = limit - extBytes;
  const out = [];
  let used = 0;
  for (const ch of stem) {
    const cp = ch.codePointAt(0);
    const w = cp <= 0x7f ? 1 : cp <= 0x7ff ? 2 : cp <= 0xffff ? 3 : 4;
    if (used + w > budget) break;
    out.push(ch);
    used += w;
  }
  return out.join('') + ext;
}

function sanitizeDownloadName(raw, fallback) {
  const fb = typeof fallback === 'string' && fallback ? fallback : FALLBACK_NAME;
  const reasons = [];
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { name: fb, changed: true, reasons: ['empty'] };
  }
  let s = stripPathComponents(raw);
  if (s !== raw) reasons.push('path-component');
  s = stripControlAndInvisible(s);
  s = stripTrailingDotsAndSpaces(s);
  let cleaned = '';
  for (const ch of s) {
    if (FORBIDDEN_ASCII.has(ch)) {
      reasons.push('forbidden-char');
      continue;
    }
    cleaned += ch;
  }
  s = cleaned;
  const beforeDevice = s;
  s = prefixReservedDevice(s);
  if (s !== beforeDevice) reasons.push('reserved-device');
  const beforeTruncate = s;
  s = truncateToBytes(s, MAX_NAME_BYTES);
  if (s !== beforeTruncate) reasons.push('too-long');
  if (!s) return { name: fb, changed: true, reasons: uniquePush(reasons, 'empty-after-clean') };
  return { name: s, changed: s !== raw, reasons };
}

function uniquePush(list, item) {
  return list.includes(item) ? list : list.concat(item);
}

function percentDecode(input) {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch !== '%') {
      out += ch;
      continue;
    }
    const hex = input.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) {
      return null;
    }
    const code = parseInt(hex, 16);
    if (code >= 0x80) {
      const bytes = [code];
      while (input[i + 3] === '%') {
        const h2 = input.slice(i + 4, i + 6);
        if (!/^[0-9a-fA-F]{2}$/.test(h2)) break;
        bytes.push(parseInt(h2, 16));
        i += 3;
      }
      try {
        out += new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
      } catch {
        return null;
      }
      i += 2;
      continue;
    }
    if (code < 0x20 || code === 0x7f) return null;
    out += String.fromCharCode(code);
    i += 2;
  }
  return out;
}

function parseContentDisposition(header) {
  if (typeof header !== 'string' || header.trim() === '') {
    return { filename: '', extended: false, reason: 'empty' };
  }
  if (header.length > 4096) return { filename: '', extended: false, reason: 'too-long-header' };
  const parts = header.split(';');
  const params = new Map();
  let star = '';
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq < 0) return { filename: '', extended: false, reason: 'malformed-parameter' };
    const key = part.slice(0, eq).trim().toLowerCase();
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"')) {
      if (!value.endsWith('"') || value.length < 2) {
        return { filename: '', extended: false, reason: 'unterminated-quote' };
      }
      value = value.slice(1, -1);
    }
    if (params.has(key)) return { filename: '', extended: false, reason: 'duplicate-parameter' };
    params.set(key, value);
    if (key === 'filename*') star = value;
  }
  if (star) {
    const firstQuote = star.indexOf("'");
    const secondQuote = star.indexOf("'", firstQuote + 1);
    if (firstQuote < 0 || secondQuote < 0) {
      return { filename: '', extended: false, reason: 'malformed-ext-value' };
    }
    const charset = star.slice(0, firstQuote).toLowerCase();
    if (charset !== 'utf-8' && charset !== 'iso-8859-1') {
      return { filename: '', extended: false, reason: 'unsupported-charset' };
    }
    const encoded = star.slice(secondQuote + 1);
    const decoded = charset === 'utf-8' ? percentDecode(encoded) : latin1Decode(encoded);
    if (decoded === null || decoded === '') {
      return { filename: '', extended: false, reason: 'bad-encoding' };
    }
    return { filename: decoded, extended: true, reason: '' };
  }
  if (params.has('filename')) {
    return { filename: params.get('filename'), extended: false, reason: '' };
  }
  return { filename: '', extended: false, reason: 'no-filename' };
}

function latin1Decode(input) {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch !== '%') {
      out += ch;
      continue;
    }
    const hex = input.slice(i + 1, i + 3);
    if (!/^[0-9a-fA-F]{2}$/.test(hex)) return null;
    out += String.fromCharCode(parseInt(hex, 16));
    i += 2;
  }
  return out;
}

module.exports = {
  MAX_NAME_BYTES,
  FALLBACK_NAME,
  sanitizeDownloadName,
  parseContentDisposition,
  stripControlAndInvisible,
  stripTrailingDotsAndSpaces,
  prefixReservedDevice,
};
