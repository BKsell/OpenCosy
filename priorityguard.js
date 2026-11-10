'use strict';
const { describeReasonTable } = require('./reasontext');
const { applyMemberListGuard } = require('./guardapply');

const { deleteHeader, firstValue, headerKey } = require('./headerutil');

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  UNKNOWN_KEY: 'unknown-key',
  BAD_URGENCY: 'bad-urgency',
  BAD_INCREMENTAL: 'bad-incremental',
  DUPLICATE_KEY: 'duplicate-key',
};

const HEADER = 'priority';
const MAX_VALUE_LENGTH = 512;
const KNOWN_KEYS = new Set(['u', 'i']);

function parseItem(token) {
  const text = token.trim();
  if (!text) return null;
  const semi = text.indexOf(';');
  const pair = semi >= 0 ? text.slice(0, semi) : text;
  const params = semi >= 0 ? text.slice(semi + 1) : '';
  const eq = pair.indexOf('=');
  const key = (eq >= 0 ? pair.slice(0, eq) : pair).trim().toLowerCase();
  const value = eq >= 0 ? pair.slice(eq + 1).replace(/"/g, '').trim() : '';
  if (!key) return null;
  return { key, value, params: params.trim() };
}

function inspectPriority(value) {
  if (typeof value !== 'string') return { reason: REASON.MALFORMED, items: [] };
  const text = value.trim();
  if (!text) return { reason: REASON.MALFORMED, items: [] };
  if (text.length > MAX_VALUE_LENGTH) return { reason: REASON.OVERLONG, items: [] };

  const seen = new Set();
  const kept = [];
  let reason = REASON.OK;
  for (const raw of text.split(',')) {
    const item = parseItem(raw);
    if (!item) continue;
    if (!KNOWN_KEYS.has(item.key)) {
      if (reason === REASON.OK) reason = REASON.UNKNOWN_KEY;
      continue;
    }
    if (seen.has(item.key)) {
      if (reason === REASON.OK) reason = REASON.DUPLICATE_KEY;
      continue;
    }
    seen.add(item.key);
    if (item.key === 'u') {
      const urgency = Number(item.value);
      if (!Number.isInteger(urgency) || urgency < 0 || urgency > 7) {
        if (reason === REASON.OK) reason = REASON.BAD_URGENCY;
        continue;
      }
      kept.push(`u=${urgency}`);
      continue;
    }
    if (item.value !== '' && item.value !== '0' && item.value !== '1' && item.value !== '?') {
      if (reason === REASON.OK) reason = REASON.BAD_INCREMENTAL;
      continue;
    }
    kept.push(item.value === '' ? 'i' : `i=${item.value}`);
  }
  if (kept.length === 0 && reason !== REASON.OK) return { reason, items: [] };
  return { reason, items: kept };
}

const describeReason = describeReasonTable({
    [REASON.OK]: 'priority 合规',
    [REASON.MISSING]: '响应未声明 priority 请求优先级',
    [REASON.MALFORMED]: 'priority 取值非法',
    [REASON.OVERLONG]: 'priority 超长',
    [REASON.UNKNOWN_KEY]: 'priority 含未知键，已剔除',
    [REASON.BAD_URGENCY]: 'priority 紧急度超出 0..7',
    [REASON.BAD_INCREMENTAL]: 'priority 增量标记取值非法',
    [REASON.DUPLICATE_KEY]: 'priority 重复键已去重',
  }, 'priority 未识别状态');

function applyPriorityGuard(headers) {
  return applyMemberListGuard(headers, HEADER, inspectPriority, { okReason: REASON.OK, missingReason: REASON.MISSING, field: 'items', wrap: false });
}

module.exports = {
  REASON,
  HEADER,
  inspectPriority,
  applyPriorityGuard,
  describeReason,
};
