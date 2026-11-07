'use strict';

const REASON = {
  OK: 'ok',
  STRIPPED: 'referer-stripped',
  ORIGIN_ONLY: 'origin-only',
  INVALID: 'invalid-url',
};

const POLICIES = new Set(['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'origin', 'origin-when-cross-origin', 'unsafe-url', 'no-referrer-when-downgrade']);

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function normalizePolicy(value) {
  const policy = String(value || '').trim().toLowerCase();
  return POLICIES.has(policy) ? policy : 'strict-origin-when-cross-origin';
}

function sameOrigin(a, b) {
  return a.protocol === b.protocol && a.host === b.host;
}

function buildReferer(sourceUrl, targetUrl, policyValue) {
  const policy = normalizePolicy(policyValue);
  const source = parse(sourceUrl);
  const target = parse(targetUrl);
  if (!source) return { value: '', reason: REASON.INVALID };
  const cross = target ? !sameOrigin(source, target) : false;
  const downgrade = target ? source.protocol === 'https:' && target.protocol === 'http:' : false;
  switch (policy) {
    case 'no-referrer':
      return { value: '', reason: REASON.STRIPPED };
    case 'same-origin':
      return cross ? { value: '', reason: REASON.STRIPPED } : { value: source.href, reason: REASON.OK };
    case 'origin':
      return { value: source.origin + '/', reason: REASON.ORIGIN_ONLY };
    case 'origin-when-cross-origin':
      return cross ? { value: source.origin + '/', reason: REASON.ORIGIN_ONLY } : { value: source.href, reason: REASON.OK };
    case 'unsafe-url':
      return downgrade ? { value: source.origin + '/', reason: REASON.ORIGIN_ONLY } : { value: source.href, reason: REASON.OK };
    case 'no-referrer-when-downgrade':
      return downgrade ? { value: '', reason: REASON.STRIPPED } : { value: source.href, reason: REASON.OK };
    case 'strict-origin':
      return downgrade ? { value: '', reason: REASON.STRIPPED } : { value: source.origin + '/', reason: REASON.ORIGIN_ONLY };
    case 'strict-origin-when-cross-origin':
    default:
      if (downgrade) return { value: '', reason: REASON.STRIPPED };
      return cross ? { value: source.origin + '/', reason: REASON.ORIGIN_ONLY } : { value: source.href, reason: REASON.OK };
  }
}

function applyRefererPolicyGuard(request) {
  const req = request && typeof request === 'object' ? request : {};
  const result = buildReferer(req.sourceUrl, req.targetUrl, req.policy);
  const headers = Object.assign({}, req.headers || {});
  if (result.value) headers.Referer = result.value;
  else delete headers.Referer;
  return {
    value: result.value,
    reason: result.reason,
    headers,
    changed: headers.Referer !== (req.headers || {}).Referer,
  };
}

function stripSensitiveQuery(value) {
  const url = parse(value);
  if (!url) return { value: '', changed: false };
  const before = url.href;
  url.search = '';
  url.hash = '';
  return { value: url.href, changed: before !== url.href };
}

function auditRefererBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let stripped = 0;
  for (const item of list) {
    const result = buildReferer(item && item.sourceUrl, item && item.targetUrl, item && item.policy);
    if (result.reason === REASON.STRIPPED) stripped += 1;
    if (result.reason !== REASON.OK) findings.push({ target: item && item.targetUrl, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { stripped, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no referer risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applyRefererPolicyGuard,
  auditRefererBatch,
  buildReferer,
  describeFindings,
  stripSensitiveQuery,
};
