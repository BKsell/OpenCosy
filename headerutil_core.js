'use strict';

function lowerKeys(headers) {
  const map = {};
  if (!headers || typeof headers !== 'object') return map;
  for (const key of Object.keys(headers)) {
    const lower = key.toLowerCase();
    if (!(lower in map)) map[lower] = key;
  }
  return map;
}

function rawValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  const raw = headers[key];
  if (raw === undefined || raw === null) return null;
  return raw;
}

function headerValues(headers, name) {
  const raw = rawValue(headers, name);
  if (raw === null) return [];
  const list = Array.isArray(raw) ? raw : [raw];
  return list.filter((item) => typeof item === 'string');
}

function headerText(headers, name) {
  const values = headerValues(headers, name);
  return values.join(', ');
}

function setHeader(headers, name, values) {
  if (!headers || typeof headers !== 'object') return;
  const key = headerKey(headers, name) || name.toLowerCase();
  headers[key] = Array.isArray(values) ? values : [values];
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

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

module.exports = { countValues, deleteHeader, firstValue, headerKey, headerText, headerValues, lowerKeys, rawValue, setHeader };
