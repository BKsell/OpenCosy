'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-features',
  NOOPENER: 'noopener-enforced',
  NOREFERRER: 'noreferrer-enforced',
  DANGEROUS_FEATURE: 'dangerous-feature',
};

const KNOWN = new Set(['width', 'height', 'left', 'top', 'menubar', 'toolbar', 'location', 'status', 'resizable', 'scrollbars', 'noopener', 'noreferrer', 'popup']);
const DANGEROUS = new Set(['alwaysontop', 'alwayslowered', 'alwaysraised', 'titlebar', 'close', 'modal', 'fullscreen']);

function parseFeatures(value) {
  if (typeof value !== 'string' || !value.trim()) return { features: {}, raw: [], invalid: [] };
  const features = {};
  const raw = [];
  const invalid = [];
  for (const part of value.split(',')) {
    const token = part.trim();
    if (!token) continue;
    const eq = token.indexOf('=');
    let key = eq < 0 ? token : token.slice(0, eq);
    let val = eq < 0 ? 'yes' : token.slice(eq + 1);
    key = key.trim().toLowerCase();
    val = val.trim().replace(/^['"]|['"]$/g, '');
    raw.push(key);
    if (!KNOWN.has(key) && !DANGEROUS.has(key)) {
      invalid.push(key);
      continue;
    }
    features[key] = val === 'yes' ? true : val;
  }
  return { features, raw, invalid };
}

function enforcePolicy(request) {
  const req = request && typeof request === 'object' ? request : {};
  const parsed = parseFeatures(req.features);
  const clean = Object.assign({}, parsed.features);
  const findings = [];
  for (const key of Object.keys(clean)) {
    if (key === 'alwaysontop' || key === 'alwayslowered' || key === 'alwaysraised' || key === 'titlebar' || key === 'modal' || key === 'fullscreen' || key === 'close') {
      delete clean[key];
      findings.push({ reason: REASON.DANGEROUS_FEATURE, detail: key });
    }
  }
  if (req.crossOrigin !== false && clean.noopener !== true) {
    clean.noopener = true;
    findings.push({ reason: REASON.NOOPENER, detail: 'noopener' });
  }
  if (req.stripReferrer !== false && clean.noreferrer !== true) {
    clean.noreferrer = true;
    findings.push({ reason: REASON.NOREFERRER, detail: 'noreferrer' });
  }
  const features = Object.keys(clean)
    .sort()
    .map((k) => k + '=' + (clean[k] === true ? 'yes' : clean[k]))
    .join(',');
  return { features, findings, invalid: parsed.invalid };
}

function applyWindowOpenFeatureGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = enforcePolicy(req);
  return {
    features: result.features,
    changed: result.features !== String(req.features || ''),
    reason: result.findings.length > 0 ? result.findings[0].reason : REASON.OK,
    findings: result.findings,
  };
}

function auditWindowOpenBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let rewritten = 0;
  for (const item of list) {
    const result = enforcePolicy(item);
    if (result.findings.length > 0) rewritten += 1;
    if (result.invalid.length > 0) findings.push({ reason: REASON.INVALID, detail: result.invalid.join(',') });
    for (const f of result.findings) findings.push({ reason: f.reason, detail: f.detail });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { rewritten, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no window.open risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyWindowOpenFeatureGuard,
  auditWindowOpenBatch,
  describeFindings,
  parseFeatures,
};
