'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  INSECURE_ENDPOINT: 'insecure-endpoint',
  ENDPOINT_CREDENTIALS: 'endpoint-credentials',
  ENDPOINT_PATH_SHAPE: 'endpoint-path-shape',
  UNSAFE_MAX_AGE: 'unsafe-max-age',
  UNKNOWN_GROUP: 'unknown-group',
};

const ENDPOINTS_HEADER = 'reporting-endpoints';
const LEGACY_HEADER = 'report-to';
const MAX_VALUE_LENGTH = 2048;
const MAX_MAX_AGE = 2592000;
const KNOWN_GROUPS = new Set(['default', 'csp-endpoint', 'nel', 'deprecation', 'intervention']);

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

function urlReason(url) {
  if (typeof url !== 'string' || !url) return REASON.MALFORMED;
  if (!/^https:\/\//i.test(url)) return REASON.INSECURE_ENDPOINT;
  if (url.includes('@')) return REASON.ENDPOINT_CREDENTIALS;
  if (url.includes('..') || url.includes('\\')) return REASON.ENDPOINT_PATH_SHAPE;
  return REASON.OK;
}

function splitPairs(text) {
  const items = [];
  let current = '';
  let inQuote = false;
  for (const ch of text) {
    if (ch === '"') inQuote = !inQuote;
    if (ch === ',' && !inQuote) {
      items.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) items.push(current);
  return items;
}

function inspectReportingEndpoints(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, endpoints: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, endpoints: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, endpoints: [] };

  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const raw of splitPairs(text)) {
    const piece = raw.trim();
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq < 0) {
      note(REASON.MALFORMED);
      continue;
    }
    const name = piece.slice(0, eq).trim().toLowerCase();
    const url = piece.slice(eq + 1).replace(/"/g, '').trim();
    if (!name || !/^[a-z0-9_-]+$/.test(name)) {
      note(REASON.MALFORMED);
      continue;
    }
    const verdict = urlReason(url);
    if (verdict !== REASON.OK) {
      note(verdict);
      continue;
    }
    kept.push({ group: name, url });
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, endpoints: [] };
  return { reason, endpoints: kept };
}

function inspectReportTo(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, groups: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, groups: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, groups: [] };

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    return { reason: REASON.MALFORMED, groups: [] };
  }
  if (!Array.isArray(parsed)) return { reason: REASON.MALFORMED, groups: [] };

  const kept = [];
  let reason = REASON.OK;
  const note = (next) => {
    if (reason === REASON.OK) reason = next;
  };

  for (const entry of parsed) {
    if (!entry || typeof entry !== 'object') {
      note(REASON.MALFORMED);
      continue;
    }
    const group = typeof entry.group === 'string' ? entry.group.trim().toLowerCase() : '';
    if (!group || !KNOWN_GROUPS.has(group)) {
      note(REASON.UNKNOWN_GROUP);
      continue;
    }
    const maxAge = entry.max_age;
    if (typeof maxAge !== 'number' || !Number.isFinite(maxAge) || maxAge < 0) {
      note(REASON.MALFORMED);
      continue;
    }
    if (maxAge > MAX_MAX_AGE) {
      note(REASON.UNSAFE_MAX_AGE);
      continue;
    }
    if (!Array.isArray(entry.endpoints) || entry.endpoints.length === 0) {
      note(REASON.MALFORMED);
      continue;
    }
    const endpoints = [];
    for (const endpoint of entry.endpoints) {
      if (!endpoint || typeof endpoint !== 'object') {
        note(REASON.MALFORMED);
        continue;
      }
      const url = typeof endpoint.url === 'string' ? endpoint.url.trim() : '';
      const verdict = urlReason(url);
      if (verdict !== REASON.OK) {
        note(verdict);
        continue;
      }
      endpoints.push({ url });
    }
    if (endpoints.length === 0) continue;
    kept.push({ group, max_age: maxAge, endpoints });
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, groups: [] };
  return { reason, groups: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return '上报端点配置合规';
    case REASON.MISSING:
      return '响应未声明上报端点';
    case REASON.MALFORMED:
      return '上报端点配置非法';
    case REASON.OVERLONG:
      return '上报端点配置超长';
    case REASON.INSECURE_ENDPOINT:
      return '上报端点不是 HTTPS，已剔除';
    case REASON.ENDPOINT_CREDENTIALS:
      return '上报端点内嵌凭据，已剔除';
    case REASON.ENDPOINT_PATH_SHAPE:
      return '上报端点包含路径穿越片段，已剔除';
    case REASON.UNSAFE_MAX_AGE:
      return '上报缓存时长超出上限，已剔除';
    case REASON.UNKNOWN_GROUP:
      return '上报分组不在白名单，已剔除';
    default:
      return '上报端点未识别状态';
  }
}

function applyReportingEndpointsGuard(headers) {
  const value = firstValue(headers, ENDPOINTS_HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, endpoints: [] };
  const result = inspectReportingEndpoints(value);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, endpoints: result.endpoints };
  }
  if (result.endpoints.length === 0) {
    deleteHeader(headers, ENDPOINTS_HEADER);
  } else {
    headers[headerKey(headers, ENDPOINTS_HEADER)] = [
      result.endpoints.map((item) => `${item.group}="${item.url}"`).join(', '),
    ];
  }
  return { changed: true, reason: result.reason, endpoints: result.endpoints };
}

function applyReportToGuard(headers) {
  const value = firstValue(headers, LEGACY_HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, groups: [] };
  const result = inspectReportTo(value);
  if (result.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, groups: result.groups };
  }
  if (result.groups.length === 0) {
    deleteHeader(headers, LEGACY_HEADER);
  } else {
    headers[headerKey(headers, LEGACY_HEADER)] = [JSON.stringify(result.groups)];
  }
  return { changed: true, reason: result.reason, groups: result.groups };
}

module.exports = {
  REASON,
  ENDPOINTS_HEADER,
  LEGACY_HEADER,
  inspectReportingEndpoints,
  inspectReportTo,
  applyReportingEndpointsGuard,
  applyReportToGuard,
  describeReason,
};
