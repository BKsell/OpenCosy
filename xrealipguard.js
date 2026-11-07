'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  BAD_PORT: 'bad-port',
};

const HEADER = 'x-real-ip';
const MAX_LENGTH = 64;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$/;
const IPV6_RE = /^\[?[0-9a-f:]+\]?(?::\d{1,5})?$/i;

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

function splitAddress(text) {
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    if (end < 0) return null;
    const host = text.slice(1, end);
    const rest = text.slice(end + 1);
    if (rest && !rest.startsWith(':')) return null;
    return { host, port: rest ? rest.slice(1) : '' };
  }
  const colon = text.lastIndexOf(':');
  if (colon < 0) return { host: text, port: '' };
  if (text.indexOf(':') !== colon) return { host: text, port: '' };
  return { host: text.slice(0, colon), port: text.slice(colon + 1) };
}

function applyXRealIpGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (text.includes(',')) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const address = splitAddress(text);
  if (!address) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (address.port) {
    const port = Number(address.port);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) {
      delete headers[headerKey(headers, HEADER)];
      return { changed: true, reason: REASON.BAD_PORT };
    }
  }
  const host = address.host;
  if (!IPV4_RE.test(host) && !IPV6_RE.test(host)) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (IPV4_RE.test(host)) {
    const octets = host.split(':')[0].split('.').map((part) => Number(part));
    if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      delete headers[headerKey(headers, HEADER)];
      return { changed: true, reason: REASON.BAD_VALUE };
    }
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyXRealIpGuard };
