'use strict';

const REASON = {
  OK: 'ok',
  LOOP_DETECTED: 'crash-loop-detected',
  TOO_FAST: 'crash-too-fast',
  NO_BACKOFF: 'crash-no-backoff',
  BUDGET_EXCEEDED: 'crash-budget-exceeded',
  INVALID_EVENT: 'crash-event-invalid',
};

const DEFAULTS = {
  maxCrashes: 3,
  windowMs: 5 * 60 * 1000,
  minIntervalMs: 10 * 1000,
  backoffBaseMs: 5 * 1000,
  maxBackoffMs: 60 * 1000,
};

function normalizeEvent(event) {
  if (!event || typeof event !== 'object') return null;
  const at = Number(event.at);
  if (!Number.isFinite(at) || at < 0) return null;
  return { at, reason: String(event.reason || 'unknown') };
}

function evaluateCrashLoop(events, options) {
  const opts = { ...DEFAULTS, ...(options || {}) };
  const list = Array.isArray(events) ? events.map(normalizeEvent) : [];
  if (list.some((item) => item === null)) {
    return { ok: false, blocked: true, reason: REASON.INVALID_EVENT, crashes: 0 };
  }
  if (list.length === 0) {
    return { ok: true, blocked: false, reason: REASON.OK, crashes: 0, backoffMs: 0 };
  }
  const sorted = list.slice().sort((a, b) => a.at - b.at);
  let recent = 0;
  const newest = sorted[sorted.length - 1].at;
  for (const item of sorted) {
    if (newest - item.at <= opts.windowMs) recent += 1;
  }
  let minGap = Infinity;
  for (let i = 1; i < sorted.length; i += 1) {
    minGap = Math.min(minGap, sorted[i].at - sorted[i - 1].at);
  }
  if (recent > opts.maxCrashes) {
    return { ok: false, blocked: true, reason: REASON.BUDGET_EXCEEDED, crashes: recent, windowMs: opts.windowMs };
  }
  if (Number.isFinite(minGap) && minGap < opts.minIntervalMs) {
    return { ok: false, blocked: true, reason: REASON.TOO_FAST, gapMs: minGap, crashes: recent };
  }
  const count = sorted.length;
  const backoffMs = Math.min(opts.maxBackoffMs, opts.backoffBaseMs * Math.pow(2, Math.max(0, count - 1)));
  if (count >= opts.maxCrashes && backoffMs < opts.backoffBaseMs) {
    return { ok: false, blocked: true, reason: REASON.NO_BACKOFF, crashes: count };
  }
  return { ok: true, blocked: false, reason: count > 1 ? REASON.OK : REASON.OK, crashes: count, backoffMs };
}

function auditCrashBatch(list, options) {
  const items = Array.isArray(list) ? list : [];
  const findings = [];
  let blocked = 0;
  for (const item of items) {
    const result = evaluateCrashLoop(item, options);
    if (result.blocked) {
      blocked += 1;
      findings.push({ reason: result.reason, crashes: result.crashes });
    }
  }
  return { total: items.length, blocked, findings };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no crash loop risk';
  return list
    .slice(0, 8)
    .map((f) => f.reason + '(' + String(f.crashes || 0) + ')')
    .join('; ');
}

module.exports = {
  REASON,
  DEFAULTS,
  evaluateCrashLoop,
  auditCrashBatch,
  describeFindings,
};
