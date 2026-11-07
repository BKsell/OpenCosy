'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  UNKNOWN_DIRECTIVE: 'unknown-directive',
  BAD_DATE: 'bad-date',
  BAD_RANGE: 'bad-range',
  OVERLONG: 'overlong',
  MALFORMED: 'malformed',
};

const MAX_VALUE_LENGTH = 256;
const BOT_PATTERN = /^(googlebot|bingbot|yandex|baiduspider|duckduckbot|slurp|teoma)\s*:\s*/i;
const TOKEN_DIRECTIVES = new Set([
  'all',
  'none',
  'noindex',
  'nofollow',
  'noarchive',
  'nosnippet',
  'notranslate',
  'noimageindex',
  'indexifembedded',
]);
const VALUE_DIRECTIVES = new Set(['max-snippet', 'max-image-preview', 'max-video-preview', 'unavailable_after']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return false;
  delete headers[key];
  return true;
}

function inspectXRobotsTag(value) {
  if (value === undefined || value === null) return { reason: REASON.MISSING };
  if (typeof value !== 'string') return { reason: REASON.MALFORMED };
  let text = value.trim();
  if (!text) return { reason: REASON.MALFORMED };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG };
  const botMatch = BOT_PATTERN.exec(text);
  const bot = botMatch ? botMatch[1].toLowerCase() : '';
  if (botMatch) text = text.slice(botMatch[0].length);
  const parts = text.split(',').map((item) => item.trim()).filter(Boolean);
  if (parts.length === 0) return { reason: REASON.MALFORMED };
  const directives = [];
  for (const part of parts) {
    const lower = part.toLowerCase();
    if (TOKEN_DIRECTIVES.has(lower)) {
      directives.push(lower);
      continue;
    }
    const split = part.split(':');
    const name = split[0].trim().toLowerCase();
    const rawValue = split.slice(1).join(':').trim();
    if (!VALUE_DIRECTIVES.has(name) || !rawValue) {
      return { reason: REASON.UNKNOWN_DIRECTIVE, directive: part.slice(0, 48) };
    }
    if (name === 'unavailable_after') {
      if (Number.isNaN(Date.parse(rawValue.replace(/\s+/g, ' '))) || rawValue.length > 64) {
        return { reason: REASON.BAD_DATE, directive: rawValue.slice(0, 48) };
      }
      directives.push(lower);
      continue;
    }
    const numeric = Number(rawValue);
    if (!Number.isInteger(numeric) || numeric < -1 || numeric > 1000000) {
      return { reason: REASON.BAD_RANGE, directive: part.slice(0, 48) };
    }
    directives.push(lower);
  }
  return { reason: REASON.OK, directives, bot };
}

function applyXRobotsGuard(headers) {
  const key = headerKey(headers, 'x-robots-tag');
  if (!key) return { changed: false, reason: REASON.MISSING };
  const raw = headers[key];
  if (Array.isArray(raw) && raw.length > 1) {
    delete headers[key];
    return { changed: true, reason: REASON.MULTI_VALUE, previous: raw.slice(0, 4) };
  }
  const value = Array.isArray(raw) ? raw[0] : raw;
  const verdict = inspectXRobotsTag(value);
  if (verdict.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, directives: verdict.directives };
  }
  delete headers[key];
  return { changed: true, reason: verdict.reason, directive: verdict.directive || null };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'X-Robots-Tag 指令合法';
    case REASON.MISSING:
      return '未声明 X-Robots-Tag';
    case REASON.UNKNOWN_DIRECTIVE:
      return 'X-Robots-Tag 使用未知指令';
    case REASON.BAD_DATE:
      return 'X-Robots-Tag unavailable_after 日期非法';
    case REASON.BAD_RANGE:
      return 'X-Robots-Tag 数值指令越界';
    case REASON.OVERLONG:
      return 'X-Robots-Tag 取值超长';
    case REASON.MALFORMED:
      return 'X-Robots-Tag 取值无法解析';
    default:
      return 'X-Robots-Tag 未知状态';
  }
}

module.exports = {
  REASON,
  inspectXRobotsTag,
  applyXRobotsGuard,
  describeReason,
};
