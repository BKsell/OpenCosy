'use strict';

function hasAsciiControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

function hasUnicodeControlChar(s) {
  if (typeof s !== 'string') return false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029 || c === 0xfeff) return true;
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

module.exports = { hasAsciiControlChar, hasUnicodeControlChar, parseUrl };
