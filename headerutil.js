'use strict';

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function firstValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return '';
  const raw = headers[key];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' ? value : '';
}

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

module.exports = { countValues, firstValue, headerKey };
