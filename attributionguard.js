'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_TOKEN: 'bad-token',
  OVERLONG: 'overlong',
  EMPTY: 'empty',
};

const ELIGIBLE_HEADER = 'attribution-reporting-eligible';
const REGISTRABLE_HEADER = 'attribution-reporting-registrable';
const ELIGIBLE = new Set(['event-source', 'navigation', 'trigger']);
const MAX_LENGTH = 256;

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

function sanitizeTokens(value, allowed) {
  const text = value.trim().toLowerCase();
  if (!text) return { kept: [], dropped: false, empty: true };
  const tokens = text.split(',');
  const kept = [];
  let dropped = false;
  for (const token of tokens) {
    const item = token.trim();
    if (!item) continue;
    if (!allowed.has(item)) {
      dropped = true;
      continue;
    }
    if (!kept.includes(item)) kept.push(item);
  }
  return { kept, dropped, empty: kept.length === 0 };
}

function applyAttributionGuard(headers) {
  let changed = false;
  let reason = REASON.MISSING;

  const eligibleKey = headerKey(headers, ELIGIBLE_HEADER);
  if (eligibleKey) {
    const value = firstValue(headers, ELIGIBLE_HEADER);
    if (value.length > MAX_LENGTH) {
      delete headers[eligibleKey];
      return { changed: true, reason: REASON.OVERLONG };
    }
    const result = sanitizeTokens(value, ELIGIBLE);
    if (result.empty) {
      delete headers[eligibleKey];
      return { changed: true, reason: REASON.EMPTY };
    }
    if (result.dropped) {
      headers[eligibleKey] = result.kept.join(', ');
      changed = true;
      reason = REASON.BAD_TOKEN;
    } else if (!changed) {
      reason = REASON.OK;
    }
  }

  const registrableKey = headerKey(headers, REGISTRABLE_HEADER);
  if (registrableKey) {
    const value = firstValue(headers, REGISTRABLE_HEADER);
    if (value.length > MAX_LENGTH) {
      delete headers[registrableKey];
      return { changed: true, reason: REASON.OVERLONG };
    }
    if (!/^[a-z0-9._~-]{1,64}$/i.test(value.trim())) {
      delete headers[registrableKey];
      return { changed: true, reason: REASON.BAD_TOKEN };
    }
    const normalized = value.trim().toLowerCase();
    if (normalized !== value.trim()) {
      headers[registrableKey] = normalized;
      changed = true;
      reason = REASON.BAD_TOKEN;
    }
    if (!changed && reason !== REASON.BAD_TOKEN) reason = REASON.OK;
  }

  return { changed, reason };
}

module.exports = { REASON, applyAttributionGuard };
