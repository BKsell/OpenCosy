'use strict';

function getResponseHeader(headers, name) {
  if (!headers || typeof headers !== 'object') return '';
  const target = String(name).toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== target) continue;
    const v = headers[key];
    if (Array.isArray(v)) return v.length ? String(v[0] || '') : '';
    return v == null ? '' : String(v);
  }
  return '';
}

function hasHeader(headers, name) {
  return getResponseHeader(headers, name).trim() !== '';
}

function letterForScore(percent) {
  if (percent >= 90) return 'A';
  if (percent >= 75) return 'B';
  if (percent >= 60) return 'C';
  if (percent >= 40) return 'D';
  return 'F';
}

// parseHstsMaxAge 解析 max-age=N，非法时返回 -1。

module.exports = { getResponseHeader, hasHeader, letterForScore };
