'use strict';

const REASON = {
  OK: 'ok',
  MISSING: 'missing',
  MALFORMED: 'malformed',
  OVERLONG: 'overlong',
  TOO_MANY: 'too-many-entries',
  PSEUDO_CODE: 'pseudo-code',
  STALE_DATE: 'stale-date',
};

const HEADER = 'warning';
const MAX_ENTRIES = 6;
const MAX_ENTRY_LENGTH = 256;
const MAX_WARNING_AGE_MS = 86400000;
const CODE_ALLOWED = new Set(['110', '111', '112', '113', '199', '214', '299']);
const PSEUDO_CODES = new Set(['1', '2', '3', '4', '5']);

function headerKey(headers, name) {
  const lower = name.toLowerCase();
  if (!headers || typeof headers !== 'object') return '';
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) return key;
  }
  return '';
}

function listValues(headers, name) {
  const key = headerKey(headers, name);
  if (!key) return [];
  const raw = headers[key];
  if (Array.isArray(raw)) return raw.filter((item) => typeof item === 'string');
  return typeof raw === 'string' ? [raw] : [];
}

function splitWarnings(values) {
  const entries = [];
  for (const value of values) {
    let current = '';
    let quoted = false;
    for (const ch of value) {
      if (ch === '"') quoted = !quoted;
      if (ch === ',' && !quoted) {
        entries.push(current);
        current = '';
        continue;
      }
      current += ch;
    }
    entries.push(current);
  }
  return entries.map((entry) => entry.trim()).filter((entry) => entry !== '');
}

function parseWarningEntry(entry, nowMs) {
  if (entry.length > MAX_ENTRY_LENGTH) return { reason: REASON.OVERLONG, code: null };
  const match = /^(\d{3})\s+([^"\s]+)\s+"([^"]*)"(?:\s+"([^"]*)")?$/.exec(entry);
  if (!match) return { reason: REASON.MALFORMED, code: null };
  const code = match[1];
  if (PSEUDO_CODES.has(code.replace(/^0+/, ''))) return { reason: REASON.PSEUDO_CODE, code };
  if (!CODE_ALLOWED.has(code)) return { reason: REASON.MALFORMED, code };
  const dateRaw = match[4];
  if (dateRaw) {
    const stamp = Date.parse(dateRaw);
    if (Number.isFinite(stamp)) {
      const age = nowMs - stamp;
      if (age > MAX_WARNING_AGE_MS || age < -MAX_WARNING_AGE_MS) {
        return { reason: REASON.STALE_DATE, code };
      }
    }
  }
  return { reason: REASON.OK, code };
}

function inspectWarning(headers, nowMs) {
  const values = listValues(headers, HEADER);
  if (values.length === 0) return { changed: false, reason: REASON.MISSING, entries: [] };
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const entries = splitWarnings(values);
  if (entries.length > MAX_ENTRIES) {
    return { changed: true, reason: REASON.TOO_MANY, entries };
  }
  for (const entry of entries) {
    const parsed = parseWarningEntry(entry, now);
    if (parsed.reason !== REASON.OK) {
      return { changed: true, reason: parsed.reason, entries };
    }
  }
  return { changed: false, reason: REASON.OK, entries };
}

function applyWarningHeaderGuard(headers, nowMs) {
  const result = inspectWarning(headers, nowMs);
  if (!result.changed) return result;
  const key = headerKey(headers, HEADER);
  if (key) delete headers[key];
  return result;
}

function describeReason(reason) {
  switch (reason) {
    case REASON.MALFORMED:
      return 'Warning 条目不符合 RFC 7234 语法';
    case REASON.OVERLONG:
      return 'Warning 条目长度超限';
    case REASON.TOO_MANY:
      return 'Warning 条目数量超限';
    case REASON.PSEUDO_CODE:
      return 'Warning 使用 1xx 伪状态码而非警告码';
    case REASON.STALE_DATE:
      return 'Warning 携带的日期与本地时间偏差过大';
    default:
      return 'Warning 头通过校验';
  }
}

module.exports = {
  REASON,
  HEADER,
  MAX_ENTRIES,
  MAX_ENTRY_LENGTH,
  CODE_ALLOWED,
  headerKey,
  listValues,
  splitWarnings,
  parseWarningEntry,
  inspectWarning,
  applyWarningHeaderGuard,
  describeReason,
};
