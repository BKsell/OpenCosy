'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  NO_REL: 'missing-rel',
  UNKNOWN_REL: 'unknown-rel',
  INSECURE: 'insecure-target',
  CREDENTIALS: 'target-credentials',
  CROSS_ORIGIN: 'cross-origin-hint',
  DUPLICATE: 'duplicate-target',
};

const HEADER = 'link';
const MAX_VALUE_LENGTH = 2048;
const ALLOWED_REL = new Set([
  'preload',
  'preconnect',
  'dns-prefetch',
  'canonical',
  'alternate',
  'next',
  'prev',
  'author',
  'license',
  'search',
  'help',
  'first',
  'last',
  'up',
]);

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

function deleteHeader(headers, name) {
  const key = headerKey(headers, name);
  if (key) delete headers[key];
}

function splitItems(text) {
  const items = [];
  let current = '';
  let inAngle = false;
  let inQuote = false;
  for (const ch of text) {
    if (ch === '<' && !inQuote) inAngle = true;
    if (ch === '>' && !inQuote) inAngle = false;
    if (ch === '"') inQuote = !inQuote;
    if (ch === ',' && !inAngle && !inQuote) {
      items.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) items.push(current);
  return items;
}

function parseItem(token) {
  const text = token.trim();
  if (!text) return null;
  if (text[0] !== '<') return null;
  const close = text.indexOf('>');
  if (close < 0) return null;
  const target = text.slice(1, close).trim();
  if (!target) return null;
  const rest = text.slice(close + 1);
  const params = {};
  for (const part of rest.split(';')) {
    const piece = part.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq < 0) {
      params[piece.toLowerCase()] = '';
      continue;
    }
    const name = piece.slice(0, eq).trim().toLowerCase();
    const value = piece.slice(eq + 1).replace(/"/g, '').trim();
    if (name) params[name] = value;
  }
  return { target, params };
}

function originOf(value) {
  if (typeof value !== 'string' || !value) return '';
  try {
    const parsed = new URL(value);
    return parsed.origin;
  } catch (err) {
    return '';
  }
}

function inspectLink(value, docOrigin) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, items: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, items: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, items: [] };

  const base = originOf(docOrigin) || docOrigin;
  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of splitItems(text)) {
    const item = parseItem(raw);
    if (!item) {
      note(REASON.MALFORMED);
      continue;
    }
    const rel = (item.params.rel || '').toLowerCase();
    if (!rel) {
      note(REASON.NO_REL);
      continue;
    }
    const relParts = rel.split(/\s+/).filter(Boolean);
    if (relParts.some((part) => !ALLOWED_REL.has(part))) {
      note(REASON.UNKNOWN_REL);
      continue;
    }
    if (item.target.includes('@')) {
      note(REASON.CREDENTIALS);
      continue;
    }
    if (/^http:\/\//i.test(item.target) || /^file:/i.test(item.target) || /^data:/i.test(item.target)) {
      note(REASON.INSECURE);
      continue;
    }
    const targetOrigin = originOf(item.target);
    const hasCrossOrigin = Object.prototype.hasOwnProperty.call(item.params, 'crossorigin');
    if (base && targetOrigin && targetOrigin !== base && !hasCrossOrigin) {
      if (relParts.includes('preload') || relParts.includes('preconnect') || relParts.includes('dns-prefetch')) {
        note(REASON.CROSS_ORIGIN);
        continue;
      }
    }
    const key = `${rel}|${item.target}`;
    if (seen.has(key)) {
      note(REASON.DUPLICATE);
      continue;
    }
    seen.add(key);
    const params = Object.keys(item.params).map((name) => {
      const captured = item.params[name];
      return captured ? `${name}=${captured}` : name;
    });
    const suffix = params.length ? `; ${params.join('; ')}` : '';
    kept.push(`<${item.target}>${suffix}`);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, items: [] };
  return { reason, items: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'link 提示合规';
    case REASON.MISSING:
      return '响应未声明 link 提示';
    case REASON.MALFORMED:
      return 'link 取值非法';
    case REASON.OVERLONG:
      return 'link 超长';
    case REASON.NO_REL:
      return 'link 缺少 rel 参数，已剔除';
    case REASON.UNKNOWN_REL:
      return 'link 关系类型不在白名单，已剔除';
    case REASON.INSECURE:
      return 'link 指向明文或本地资源，已剔除';
    case REASON.CREDENTIALS:
      return 'link 目标内嵌凭据，已剔除';
    case REASON.CROSS_ORIGIN:
      return 'link 跨源预载未声明 crossorigin，已剔除';
    case REASON.DUPLICATE:
      return 'link 重复目标已去重';
    default:
      return 'link 未识别状态';
  }
}

function applyLinkResponseGuard(headers, docOrigin) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, items: [] };
  const result = inspectLink(value, docOrigin);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, items: result.items };
  }
  if (result.items.length === 0) {
    deleteHeader(headers, HEADER);
  } else {
    headers[headerKey(headers, HEADER)] = [result.items.join(', ')];
  }
  return { changed: true, reason: result.reason, items: result.items };
}

module.exports = {
  REASON,
  HEADER,
  inspectLink,
  applyLinkResponseGuard,
  describeReason,
};
