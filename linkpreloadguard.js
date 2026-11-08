'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  CROSS_ORIGIN: 'cross-origin',
  BAD_SCHEME: 'bad-scheme',
  TOO_MANY: 'too-many',
};

const MAX_LINKS = 8;
const MAX_HEADER_LENGTH = 2048;
const MAX_HREF_LENGTH = 512;

const CROSS_ORIGIN_RELS = new Set(['preload', 'prefetch', 'preconnect', 'dns-prefetch']);

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

function splitLinks(value) {
  const parts = [];
  let depth = 0;
  let quoted = false;
  let start = 0;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '"') {
      quoted = !quoted;
      continue;
    }
    if (ch === '<') depth += 1;
    else if (ch === '>') depth = Math.max(0, depth - 1);
    else if (ch === ',' && depth === 0 && !quoted) {
      parts.push(value.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(value.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part.length > 0);
}

function parseLink(entry) {
  const match = /^<([^>]{1,512})>\s*(?:;\s*(.+))?$/.exec(entry);
  if (!match) return null;
  const href = match[1].trim();
  const params = {};
  const tail = match[2] || '';
  for (const rawParam of tail.split(';')) {
    const piece = rawParam.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq < 0) {
      params[piece.toLowerCase()] = '';
      continue;
    }
    const name = piece.slice(0, eq).trim().toLowerCase();
    let value = piece.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    params[name] = value;
  }
  return { href, params };
}

function originOf(value) {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return parsed.origin;
  } catch {
    return '';
  }
}

function inspectLinks(headers, details) {
  const value = firstValue(headers, 'link');
  if (!value) return { changed: false, reason: REASON.MISSING, kept: [], findings: [] };
  if (value.length > MAX_HEADER_LENGTH) {
    return { changed: true, reason: REASON.MALFORMED, kept: [], findings: [{ reason: REASON.MALFORMED }] };
  }
  const baseUrl = details && typeof details.url === 'string' ? details.url : '';
  const entries = splitLinks(value);
  if (entries.length > MAX_LINKS) {
    return { changed: true, reason: REASON.TOO_MANY, kept: [], findings: [{ reason: REASON.TOO_MANY }] };
  }
  const base = details && typeof details.url === 'string' ? originOf(details.url) : '';
  const kept = [];
  const findings = [];
  for (const entry of entries) {
    const parsed = parseLink(entry);
    if (!parsed) {
      findings.push({ reason: REASON.MALFORMED, entry });
      continue;
    }
    if (parsed.href.length > MAX_HREF_LENGTH) {
      findings.push({ reason: REASON.MALFORMED, entry });
      continue;
    }
    const rel = (parsed.params.rel || '').toLowerCase();
    let resolved = '';
    try {
      resolved = baseUrl ? new URL(parsed.href, baseUrl).href : parsed.href;
    } catch {
      resolved = '';
    }
    if (!originOf(resolved)) {
      findings.push({ reason: REASON.BAD_SCHEME, href: parsed.href });
      continue;
    }
    const rels = rel.split(/\s+/).filter(Boolean);
    const sensitive = rels.some((item) => CROSS_ORIGIN_RELS.has(item));
    if (sensitive && base && originOf(resolved) !== base) {
      findings.push({ reason: REASON.CROSS_ORIGIN, href: parsed.href });
      continue;
    }
    kept.push(entry);
  }
  if (!findings.length) {
    return { changed: false, reason: REASON.OK, kept, findings };
  }
  const reason = findings.some((item) => item.reason === REASON.TOO_MANY)
    ? REASON.TOO_MANY
    : findings.some((item) => item.reason === REASON.CROSS_ORIGIN)
      ? REASON.CROSS_ORIGIN
      : findings.some((item) => item.reason === REASON.BAD_SCHEME)
        ? REASON.BAD_SCHEME
        : REASON.MALFORMED;
  return { changed: true, reason, kept, findings };
}

function applyLinkPreloadGuard(headers, details) {
  const result = inspectLinks(headers, details);
  if (!result.changed) return result;
  const key = headerKey(headers, 'link');
  if (!key) return result;
  if (result.kept.length === 0) {
    delete headers[key];
    return result;
  }
  headers[key] = [result.kept.join(', ')];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Link 头声明格式非法';
    case REASON.CROSS_ORIGIN:
      return 'Link 头指向第三方源';
    case REASON.BAD_SCHEME:
      return 'Link 头使用非 HTTP(S) 目标';
    case REASON.TOO_MANY:
      return 'Link 头条目数量超预算';
    case REASON.MISSING:
      return '未声明 Link 头';
    default:
      return 'Link 头通过校验';
  }
}

module.exports = {
  REASON,
  MAX_LINKS,
  MAX_HEADER_LENGTH,
  splitLinks,
  parseLink,
  inspectLinks,
  applyLinkPreloadGuard,
  describeReason,
};
