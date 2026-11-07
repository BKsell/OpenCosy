'use strict';

const REASON = {
  OK: 'ok',
  NO_CONSENT: 'no-consent',
  OPT_OUT: 'opted-out',
  SENSITIVE_FIELD: 'sensitive-field',
  IDENTIFIER: 'stable-identifier',
  CROSS_BORDER: 'cross-border-transfer',
};

const SENSITIVE = new Set(['email', 'username', 'ip', 'hostname', 'path', 'mac', 'serial', 'token', 'cookie', 'url', 'uuid', 'machineid']);

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  if (req.optedOut === true) return { allowed: false, reason: REASON.OPT_OUT };
  if (req.consent !== true) return { allowed: false, reason: REASON.NO_CONSENT };
  const fields = Array.isArray(req.fields) ? req.fields.map((f) => String(f).toLowerCase()) : [];
  const sensitive = fields.filter((f) => SENSITIVE.has(f));
  if (sensitive.length > 0) return { allowed: false, reason: REASON.SENSITIVE_FIELD, fields: sensitive };
  if (req.stableIdentifier && !req.identifierRotated) {
    return { allowed: false, reason: REASON.IDENTIFIER, fields: [String(req.stableIdentifier)] };
  }
  if (Array.isArray(req.endpointHosts) && req.endpointHosts.some((h) => /\.(cn|ru|ir)$/i.test(String(h)))) {
    return { allowed: false, reason: REASON.CROSS_BORDER };
  }
  return { allowed: true, reason: REASON.OK };
}

function sanitizePayload(payload, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const out = {};
  const dropped = [];
  const source = payload && typeof payload === 'object' ? payload : {};
  const allowed = Array.isArray(opts.allowFields) ? opts.allowFields.map((f) => String(f).toLowerCase()) : [];
  for (const key of Object.keys(source)) {
    const lower = key.toLowerCase();
    if (SENSITIVE.has(lower)) {
      dropped.push(key);
      continue;
    }
    if (allowed.length > 0 && !allowed.includes(lower)) {
      dropped.push(key);
      continue;
    }
    out[key] = source[key];
  }
  return { payload: out, dropped };
}

function applyTelemetryConsentGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = evaluate(req);
  const payload = result.allowed && req.payload ? sanitizePayload(req.payload, req.options) : { payload: {}, dropped: [] };
  return {
    allowed: result.allowed,
    reason: result.reason,
    fields: result.fields || [],
    payload: payload.payload,
    dropped: payload.dropped,
  };
}

function auditTelemetryBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let blocked = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (!result.allowed) blocked += 1;
    if (result.reason !== REASON.OK) findings.push({ endpoint: item && item.endpoint, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { blocked, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no telemetry consent risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyTelemetryConsentGuard,
  auditTelemetryBatch,
  describeFindings,
  sanitizePayload,
};
