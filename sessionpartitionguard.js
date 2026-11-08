'use strict';

const REASON = {
  OK: 'ok',
  INVALID: 'invalid-url',
  THIRD_PARTY_EPHEMERAL: 'third-party-ephemeral',
  PARTITION_COLLISION: 'partition-collision',
  OPAQUE: 'opaque-origin',
  INSECURE: 'insecure-origin',
};

const PARTITION_RE = /^persist:[a-z0-9._-]{1,64}$/;

function parse(value) {
  if (typeof value !== 'string' || !value) return null;
  try {
    return new URL(value);
  } catch (err) {
    return null;
  }
}

function siteKey(host) {
  const parts = String(host || '').toLowerCase().split('.');
  if (parts.length < 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

function partitionFor(url, options) {
  const opts = options && typeof options === 'object' ? options : {};
  const parsed = parse(url);
  if (!parsed) return { partition: '', reason: REASON.INVALID, ephemeral: true };
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { partition: '', reason: REASON.OPAQUE, ephemeral: true };
  }
  if (parsed.protocol === 'http:' && !opts.allowInsecure) {
    return { partition: '', reason: REASON.INSECURE, ephemeral: true };
  }
  const site = siteKey(parsed.hostname).replace(/[^a-z0-9._-]/g, '_');
  const persist = Boolean(opts.persist);
  if (persist) return { partition: 'persist:' + site.slice(0, 64), reason: REASON.OK, ephemeral: false };
  return { partition: 'session:' + site.slice(0, 64), reason: REASON.OK, ephemeral: true };
}

function evaluate(request) {
  const req = request && typeof request === 'object' ? request : {};
  const target = parse(req.url);
  const firstParty = parse(req.topUrl);
  if (!target) return { partition: '', ephemeral: true, reason: REASON.INVALID };
  if (!firstParty) {
    return Object.assign(partitionFor(req.url, req.options), { thirdParty: true });
  }
  const thirdParty = !req.sameParty && siteKey(target.hostname) !== siteKey(firstParty.hostname);
  if (thirdParty && !req.allowThirdPartyStorage) {
    return { partition: '', ephemeral: true, reason: REASON.THIRD_PARTY_EPHEMERAL, thirdParty: true };
  }
  const result = partitionFor(req.url, Object.assign({}, req.options, { persist: thirdParty ? false : req.options && req.options.persist }));
  return Object.assign(result, { thirdParty });
}

function applySessionPartitionGuard(request) {
  const result = evaluate(request);
  const opts = {};
  if (result.partition) opts.partition = result.partition;
  return {
    partition: result.partition,
    ephemeral: Boolean(result.ephemeral),
    thirdParty: Boolean(result.thirdParty),
    reason: result.reason,
    webPreferences: opts,
  };
}

function validatePartitionName(value) {
  if (typeof value !== 'string' || !value) return { valid: false, reason: REASON.INVALID };
  if (!PARTITION_RE.test(value)) return { valid: false, reason: REASON.PARTITION_COLLISION };
  return { valid: true, reason: REASON.OK };
}

function auditPartitionBatch(requests, options) {
  const list = Array.isArray(requests) ? requests : [];
  const findings = [];
  let ephemeral = 0;
  for (const item of list) {
    const result = evaluate(item);
    if (result.ephemeral) ephemeral += 1;
    if (result.reason !== REASON.OK) findings.push({ url: item && item.url, reason: result.reason });
  }
  const limit = Number(options && options.maxFindings) || 10;
  return { ephemeral, total: list.length, findings: findings.slice(0, limit) };
}

function describeFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  if (list.length === 0) return 'no partition risk';
  return list.slice(0, 8).map((f) => f.reason).join('; ');
}

module.exports = {
  REASON,
  applySessionPartitionGuard,
  auditPartitionBatch,
  describeFindings,
  partitionFor,
  validatePartitionName,
};
