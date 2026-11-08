'use strict';

const REASON = {
  OK: 'ok',
  ID_MISSING: 'crash-id-missing',
  ID_FORMAT: 'crash-id-format',
  ID_TOO_SHORT: 'crash-id-too-short',
  ID_DUPLICATE: 'crash-id-duplicate',
  PII_IN_REPORT: 'crash-report-pii',
  PAYLOAD_TOO_LARGE: 'crash-report-too-large',
};

const ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const MAX_REPORT = 65536;

function evaluateCrashReport(report, seen) {
  const item = report || {};
  const id = String(item.id || '').trim();
  if (id === '') return { ok: false, blocked: true, reason: REASON.ID_MISSING, id };
  if (!ID_PATTERN.test(id)) return { ok: false, blocked: true, reason: REASON.ID_FORMAT, id: id.slice(0, 64) };
  if (id.replace(/-/g, '').length < 32) return { ok: false, blocked: true, reason: REASON.ID_TOO_SHORT, id };
  if (seen instanceof Set && seen.has(id)) {
    return { ok: false, blocked: true, reason: REASON.ID_DUPLICATE, id };
  }
  const payload = typeof item.payload === 'string' ? item.payload : JSON.stringify(item.payload || {});
  if (payload.length > MAX_REPORT) {
    return { ok: false, blocked: true, reason: REASON.PAYLOAD_TOO_LARGE, id, size: payload.length };
  }
  const pii = item.pii || {};
  if (pii.email === true || pii.username === true || pii.ip === true || pii.machineId === true) {
    return { ok: false, blocked: true, reason: REASON.PII_IN_REPORT, id, fields: Object.keys(pii) };
  }
  return { ok: true, blocked: false, reason: REASON.OK, id, size: payload.length };
}

function auditCrashBatch(list, seen) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  const registry = seen instanceof Set ? seen : new Set();
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCrashReport(item, registry);
    if (result.blocked) {
      blocked += 1;
      findings.push({ id: result.id, reason: result.reason });
    }
    if (result.ok) registry.add(result.id);
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no crash report risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.id || '') + ')')
    .join('; ');
}

module.exports = {
  REASON,
  evaluateCrashReport,
  auditCrashBatch,
  describeFindings,
};
