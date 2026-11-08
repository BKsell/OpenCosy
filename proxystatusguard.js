'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  DETAILS_LEAK: 'details-leak',
  INTERNAL_AGENT: 'internal-agent',
  CREDENTIALS: 'agent-credentials',
  DUPLICATE: 'duplicate-entry',
};

const HEADER = 'proxy-status';
const MAX_VALUE_LENGTH = 1024;
const LEAKY_PARAMS = new Set(['details', 'next-hop-ip', 'next-hop-protocol', 'proxy-internal-id']);

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

function parseItem(token) {
  const text = token.trim();
  if (!text) return null;
  const parts = [];
  let current = '';
  let inQuote = false;
  for (const ch of text) {
    if (ch === '"') inQuote = !inQuote;
    if (ch === ';' && !inQuote) {
      parts.push(current);
      current = '';
      continue;
    }
    current += ch;
  }
  parts.push(current);
  const agent = parts[0].trim();
  if (!agent) return null;
  const params = [];
  for (const raw of parts.slice(1)) {
    const piece = raw.trim();
    if (piece) params.push(piece);
  }
  return { agent, params };
}

function paramName(value) {
  const eq = value.indexOf('=');
  return (eq >= 0 ? value.slice(0, eq) : value).trim().toLowerCase();
}

function inspectProxyStatus(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, items: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, items: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, items: [] };

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
    if (item.agent.includes('@')) {
      note(REASON.CREDENTIALS);
      continue;
    }
    if (item.agent.includes(':') || item.agent.includes('/') || /\d+\.\d+\.\d+\.\d+/.test(item.agent)) {
      note(REASON.INTERNAL_AGENT);
      continue;
    }
    const keptParams = [];
    for (const param of item.params) {
      if (LEAKY_PARAMS.has(paramName(param))) {
        note(REASON.DETAILS_LEAK);
        continue;
      }
      keptParams.push(param);
    }
    const key = `${item.agent}|${keptParams.join(';')}`;
    if (seen.has(key)) {
      note(REASON.DUPLICATE);
      continue;
    }
    seen.add(key);
    kept.push(keptParams.length ? `${item.agent}; ${keptParams.join('; ')}` : item.agent);
  }

  if (kept.length === 0 && reason !== REASON.OK) return { reason, items: [] };
  return { reason, items: kept };
}

function describeReason(reason) {
  switch (reason) {
    case REASON.OK:
      return 'proxy-status 合规';
    case REASON.MISSING:
      return '响应未声明 proxy-status';
    case REASON.MALFORMED:
      return 'proxy-status 取值非法';
    case REASON.OVERLONG:
      return 'proxy-status 超长';
    case REASON.DETAILS_LEAK:
      return 'proxy-status 携带内部诊断细节，已剔除';
    case REASON.INTERNAL_AGENT:
      return 'proxy-status 暴露内部地址或路径形态的代理标识，已剔除';
    case REASON.CREDENTIALS:
      return 'proxy-status 代理标识内嵌凭据，已剔除';
    case REASON.DUPLICATE:
      return 'proxy-status 重复条目已去重';
    default:
      return 'proxy-status 未识别状态';
  }
}

function applyProxyStatusGuard(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, items: [] };
  const result = inspectProxyStatus(value);
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
  inspectProxyStatus,
  applyProxyStatusGuard,
  describeReason,
};
