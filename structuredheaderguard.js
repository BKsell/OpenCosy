'use strict';

const { headerKey, rawValue } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  TOO_LONG: 'too-long',
};

function applyStructuredHeaderGuard(headers, spec) {
  const raw = rawValue(headers, spec.header);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, spec.header);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(',') : String(raw);
  if (text.length > spec.maxLength) {
    delete headers[key];
    return { changed: true, reason: REASON.TOO_LONG };
  }
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const entries = text.split(',').map((v) => v.trim()).filter(Boolean);
  if (entries.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (entries.length > spec.maxEntries) {
    headers[key] = entries.slice(0, spec.maxEntries).join(', ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  const safe = [];
  let dropped = false;
  const seen = new Set();
  for (const entry of entries) {
    const eq = entry.indexOf('=');
    const name = eq > 0 ? entry.slice(0, eq) : '';
    if (!spec.member.test(entry) || seen.has(name)) {
      dropped = true;
      continue;
    }
    seen.add(name);
    safe.push(entry);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (dropped) {
    headers[key] = safe.join(', ');
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyStructuredHeaderGuard };
