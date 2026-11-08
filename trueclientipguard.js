'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  PRIVATE: 'private-address',
};

const HEADER = 'true-client-ip';
const MAX_LENGTH = 64;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-f:.]{2,45}$/i;

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

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function inspectAddress(text) {
  if (IPV4_RE.test(text)) {
    return isPrivateIPv4(text) ? REASON.PRIVATE : REASON.OK;
  }
  if (IPV6_RE.test(text) && text.includes(':')) {
    if (text === '::1' || text.startsWith('fe80:') || text.startsWith('fc') || text.startsWith('fd')) {
      return REASON.PRIVATE;
    }
    return REASON.OK;
  }
  return REASON.BAD_VALUE;
}

function applyTrueClientIpGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING };
  const parts = value.split(',').map((part) => part.trim()).filter(Boolean);
  if (parts.length > 1) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const text = value.trim();
  if (!text) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.MISSING };
  }
  if (text.length > MAX_LENGTH) {
    delete headers[headerKey(headers, HEADER)];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const verdict = inspectAddress(text);
  if (verdict === REASON.OK) return { changed: false, reason: REASON.OK };
  delete headers[headerKey(headers, HEADER)];
  return { changed: true, reason: verdict };
}

module.exports = { REASON, applyTrueClientIpGuard, inspectAddress };
