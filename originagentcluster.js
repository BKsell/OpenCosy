'use strict';
const { describeReasonFrom } = require('./reasontext');

const { firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  TIGHTENED: 'tightened',
  LENIENT: 'lenient',
};

const HEADER = 'origin-agent-cluster';
const STRICT = '?1';
const LENIENT_VALUE = '?0';
const MAX_VALUE_LENGTH = 32;

function parseOriginAgentCluster(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, strict: null };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, strict: null };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.MALFORMED, strict: null };
  if (text === STRICT) return { reason: REASON.OK, strict: true };
  if (text === LENIENT_VALUE) return { reason: REASON.LENIENT, strict: false };
  if (/^\?[01]$/.test(text)) return { reason: REASON.MALFORMED, strict: null };
  if (/^[01]$/.test(text)) return { reason: REASON.MALFORMED, strict: null };
  return { reason: REASON.MALFORMED, strict: null };
}

function inspectOriginAgentCluster(headers) {
  const value = firstValue(headers, HEADER);
  if (!value) return { changed: false, reason: REASON.MISSING, strict: null };
  const parsed = parseOriginAgentCluster(value);
  if (parsed.reason === REASON.OK) {
    return { changed: false, reason: REASON.OK, strict: true };
  }
  if (parsed.reason === REASON.LENIENT) {
    return { changed: true, reason: REASON.TIGHTENED, strict: true };
  }
  return { changed: true, reason: REASON.MALFORMED, strict: true };
}

function applyOriginAgentClusterGuard(headers) {
  const result = inspectOriginAgentCluster(headers);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) headers[key] = STRICT;
  return result;
}

function describeReason(reason) {
  return describeReasonFrom({
    [REASON.MISSING]: '响应缺少 Origin-Agent-Cluster',
    [REASON.MALFORMED]: 'Origin-Agent-Cluster 取值非法，已收紧为 ?1',
    [REASON.TIGHTENED]: 'Origin-Agent-Cluster 显式放开，已收紧为 ?1',
  }, reason, 'Origin-Agent-Cluster 已强制同源隔离');
}

module.exports = {
  REASON,
  HEADER,
  STRICT,
  LENIENT_VALUE,
  MAX_VALUE_LENGTH,
  headerKey,
  firstValue,
  parseOriginAgentCluster,
  inspectOriginAgentCluster,
  applyOriginAgentClusterGuard,
  describeReason,
};
