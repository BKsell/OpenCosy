'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  BAD_VALUE: 'bad-value',
  TOO_MANY: 'too-many',
  DUPLICATE: 'duplicate',
};

const HEADER = 'feature-policy';
const FEATURES = new Set([
  'accelerometer', 'ambient-light-sensor', 'autoplay', 'camera', 'clipboard-read',
  'clipboard-write', 'cross-origin-isolated', 'display-capture', 'document-domain',
  'encrypted-media', 'execution-while-not-rendered', 'execution-while-out-of-viewport',
  'fullscreen', 'geolocation', 'gyroscope', 'hid', 'idle-detection', 'magnetometer',
  'microphone', 'midi', 'navigation-override', 'payment', 'picture-in-picture',
  'publickey-credentials-get', 'screen-wake-lock', 'serial', 'sync-xhr',
  'usb', 'web-share', 'xr-spatial-tracking',
]);
const ALLOWLIST_ITEM = /^'?(self|src|none|\*)'?$/i;
const MAX_DIRECTIVES = 24;

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function rawValue(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return null;
  return headers[key];
}

function splitDirectives(text) {
  const parts = [];
  let current = '';
  let quoted = false;
  for (const char of text) {
    if (char === "'") quoted = !quoted;
    if (char === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts.map((v) => v.trim()).filter(Boolean);
}

function applyFeaturePolicyGuard(headers) {
  const raw = rawValue(headers, HEADER);
  if (raw === null) return { changed: false, reason: REASON.MISSING };
  const key = headerKey(headers, HEADER);
  const text = Array.isArray(raw) ? raw.map((v) => String(v)).join(';') : String(raw);
  if (/[\u0000-\u0008\u000a-\u001f\u007f]/.test(text)) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  const directives = splitDirectives(text);
  if (directives.length === 0) {
    delete headers[key];
    return { changed: true, reason: REASON.BAD_VALUE };
  }
  if (directives.length > MAX_DIRECTIVES) {
    headers[key] = directives.slice(0, MAX_DIRECTIVES).join('; ');
    return { changed: true, reason: REASON.TOO_MANY };
  }
  let reason = REASON.OK;
  const safe = [];
  const seen = new Set();
  for (const directive of directives) {
    const space = directive.indexOf(' ');
    const name = (space > 0 ? directive.slice(0, space) : directive).toLowerCase();
    if (!FEATURES.has(name)) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    if (seen.has(name)) {
      reason = REASON.DUPLICATE;
      continue;
    }
    const rest = space > 0 ? directive.slice(space + 1).trim() : '';
    if (!rest) {
      reason = REASON.BAD_VALUE;
      continue;
    }
    for (const item of rest.split(/\s+/)) {
      if (ALLOWLIST_ITEM.test(item)) continue;
      if (/^https:\/\/[^\s;]{1,255}$/.test(item)) continue;
      reason = REASON.BAD_VALUE;
    }
    seen.add(name);
    safe.push(rest ? `${name} ${rest}` : name);
  }
  if (safe.length === 0) {
    delete headers[key];
    return { changed: true, reason: reason === REASON.OK ? REASON.BAD_VALUE : reason };
  }
  if (reason !== REASON.OK) {
    headers[key] = safe.join('; ');
    return { changed: true, reason };
  }
  return { changed: false, reason: REASON.OK };
}

module.exports = { REASON, applyFeaturePolicyGuard };
