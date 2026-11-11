"use strict";

const path = require('path');

const IS_WIN = process.platform === 'win32';

function foldCase(s) {
  return IS_WIN ? s.toLowerCase() : s;
}

function trimTrailingSep(s) {
  let out = s;
  const root = path.parse(out).root;
  while (out.length > root.length && (out[out.length - 1] === '/' || out[out.length - 1] === '\\')) {
    out = out.slice(0, -1);
  }
  return out;
}

function stripExtended(s) {
  if (s === '') return '';
  const low = s.toLowerCase();
  if (low.startsWith('\\\\?\\unc\\')) return '\\\\' + s.slice(8);
  if (low.startsWith('\\\\?\\')) return s.slice(4);
  if (s.startsWith('\\??\\')) return s.slice(4);
  return s;
}

function splitSegments(s) {
  const parts = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '/' || c === '\\') {
      parts.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  parts.push(cur);
  return parts;
}

function hasDriveLetter(seg) {
  if (seg.length !== 2 || seg[1] !== ':') return false;
  const c = seg.charCodeAt(0);
  const upper = c >= 65 && c <= 90;
  const lower = c >= 97 && c <= 122;
  return upper || lower;
}

module.exports = { IS_WIN, foldCase, trimTrailingSep, stripExtended, splitSegments, hasDriveLetter };
