'use strict';
const { describeReasonTable } = require('./reasontext');
const { applyMemberListGuard } = require('./guardapply');

const { splitItems } = require('./modutil');

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

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

const describeReason = describeReasonTable({
    [REASON.OK]: 'proxy-status 合规',
    [REASON.MISSING]: '响应未声明 proxy-status',
    [REASON.MALFORMED]: 'proxy-status 取值非法',
    [REASON.OVERLONG]: 'proxy-status 超长',
    [REASON.DETAILS_LEAK]: 'proxy-status 携带内部诊断细节，已剔除',
    [REASON.INTERNAL_AGENT]: 'proxy-status 暴露内部地址或路径形态的代理标识，已剔除',
    [REASON.CREDENTIALS]: 'proxy-status 代理标识内嵌凭据，已剔除',
    [REASON.DUPLICATE]: 'proxy-status 重复条目已去重',
  }, 'proxy-status 未识别状态');

function applyProxyStatusGuard(headers) {
  return applyMemberListGuard(headers, HEADER, inspectProxyStatus, { okReason: REASON.OK, missingReason: REASON.MISSING, field: 'items', wrap: false });
}

module.exports = {
  REASON,
  HEADER,
  inspectProxyStatus,
  applyProxyStatusGuard,
  describeReason,
};
