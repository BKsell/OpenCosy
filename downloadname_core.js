
const { MAX_NAME_BYTES, FALLBACK_NAME, FORBIDDEN_ASCII, RESERVED_DEVICE, isInvisibleCodePoint, stripControlAndInvisible, stripPathComponents, stripTrailingDotsAndSpaces, splitStemExt, deviceSegment, prefixReservedDevice, byteLength, truncateToBytes, sanitizeDownloadName, uniquePush } = require('./downloadnamesanitize_core');
'use strict';

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

function splitDispositionParams(header) {
  const parts = [];
  let current = '';
  let quoted = false;
  let escaped = false;
  for (let i = 0; i < header.length; i += 1) {
    const ch = header[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (quoted && ch === '\\') {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      quoted = !quoted;
      current += ch;
      continue;
    }
    if (ch === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (quoted) return null;
  parts.push(current);
  return parts;
}

function unquoteDispositionValue(value) {
  if (!value.startsWith('"')) return value;
  if (value.length < 2 || !value.endsWith('"')) return null;
  const inner = value.slice(1, -1);
  let out = '';
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (ch === '\\' && i + 1 < inner.length) {
      out += inner[i + 1];
      i += 1;
      continue;
    }
    if (ch === '"') return null;
    out += ch;
  }
  return out;
}

function parseContentDisposition(header) {
  if (typeof header !== 'string' || header.trim() === '') {
    return { filename: '', extended: false, reason: 'empty' };
  }
  if (header.length > 4096) return { filename: '', extended: false, reason: 'too-long-header' };
  const parts = splitDispositionParams(header);
  if (!parts) return { filename: '', extended: false, reason: 'unterminated-quote' };
  const params = new Map();
  let star = '';
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq < 0) return { filename: '', extended: false, reason: 'malformed-parameter' };
    const key = part.slice(0, eq).trim().toLowerCase();
    const rawValue = part.slice(eq + 1).trim();
    const value = unquoteDispositionValue(rawValue);
    if (value === null) {
      return { filename: '', extended: false, reason: 'unterminated-quote' };
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

function hasInvisibleCodePoint(raw) {
  for (const ch of String(raw)) {
    if (isInvisibleCodePoint(ch.codePointAt(0))) return true;
  }
  return false;
}

module.exports = {
  MAX_NAME_BYTES,
  FALLBACK_NAME,
  sanitizeDownloadName,
  parseContentDisposition,
  stripControlAndInvisible,
  stripTrailingDotsAndSpaces,
  prefixReservedDevice,
  splitDispositionParams,
  unquoteDispositionValue,
  hasInvisibleCodePoint,
  isInvisibleCodePoint,
};
