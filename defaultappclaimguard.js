'use strict';

const REASON = {
  CLAIM_SCHEME_UNKNOWN: 'claim-scheme-unknown',
  CLAIM_BROAD_RISK: 'claim-broad-risk',
  CLAIM_LIMIT: 'claim-limit',
  CLAIM_EMPTY: 'claim-empty',
};

const LIMITS = {
  MAX_CLAIMS: 3,
};

function pick(source, path) {
  let current = source;
  for (const part of path.split('.')) {
    if (!current || typeof current !== 'object') return undefined;
    current = current[part];
  }
  return current;
}

function text(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function evaluateDefaultAppClaimGuard(snapshot, options) {
  const data = snapshot || {};
  const opts = options || {};
  const findings = [];
  const add = (reason, detail, blocking) => {
    findings.push({ reason, detail, blocking: blocking === true });
  };

  const claim_scheme_unknownList = Array.isArray(pick(data, 'claimed')) ? pick(data, 'claimed') : [];
  const claim_scheme_unknownHit = claim_scheme_unknownList.some((item) => !['https', 'mailto', 'webcal', 'tel'].includes(String((item && typeof item === 'object' ? item : item) || '').toLowerCase()));
  if (claim_scheme_unknownHit) {
    add(REASON.CLAIM_SCHEME_UNKNOWN, '声明了非预期协议', true);
  }

  if (pick(data, 'allowsBroadClaim') === true) {
    add(REASON.CLAIM_BROAD_RISK, '声明接管全部 HTTP(S) 链接', true);
  }

  const claim_limitList = Array.isArray(pick(data, 'claimed')) ? pick(data, 'claimed') : [];
  if (claim_limitList.length > 3) {
    add(REASON.CLAIM_LIMIT, '默认应用声明数量超出上限', false);
  }

  const claim_emptyList = Array.isArray(pick(data, 'claimed')) ? pick(data, 'claimed') : [];
  if (claim_emptyList.length === 0) {
    add(REASON.CLAIM_EMPTY, '默认应用声明为空', false);
  }

  return {
    findings,
    blocking: findings.some((finding) => finding.blocking),
    warnings: findings.filter((finding) => finding.blocking !== true),
    options: opts,
  };
}

function describeDefaultAppClaimGuard(result) {
  if (!result || !Array.isArray(result.findings) || result.findings.length === 0) {
    return 'no findings';
  }
  return result.findings
    .map((finding) => finding.reason + ': ' + finding.detail)
    .join('; ');
}

module.exports = { REASON, LIMITS, evaluateDefaultAppClaimGuard, describeDefaultAppClaimGuard };
