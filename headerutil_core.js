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

function firstText(headers, name) {
  return firstValue(headers, name).trim();
}

function firstTextLower(headers, name) {
  return firstText(headers, name).toLowerCase();
}

function countValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return 0;
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.length;
  return typeof raw === 'string' ? 1 : 0;
}

function inspectSingleHeader(headers, header, parse, missingReason, multiReason, okReason) {
  const value = firstValue(headers, header);
  if (!value) return { changed: false, reason: missingReason, parsed: null };
  if (countValues(headers, header) > 1) return { changed: true, reason: multiReason, parsed: null };
  const parsed = parse(value);
  if (parsed.reason === okReason) return { changed: false, reason: okReason, parsed };
  return { changed: true, reason: parsed.reason, parsed };
}

module.exports = { countValues, deleteHeader, firstText, firstTextLower, firstValue, headerKey, headerText, headerValues, inspectSingleHeader, lowerKeys, rawValue, setHeader };
